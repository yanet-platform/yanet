#!/usr/bin/env python3

"""Build YANET test targets and run memory-bounded autotest batches."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Callable,
    Literal,
    NamedTuple,
    Protocol,
    Sequence,
    TextIO,
    TypeAlias,
    cast,
)


REPOSITORY_ROOT = Path(__file__).resolve().parent
ISOLATED_GROUP = Path("/tmp/yanet-autotest-group")
DEFAULT_AUTOTEST_GROUP = Path("autotest/units/001_one_port")
DEFAULT_BUILDER_IMAGE = "yanetplatform/builder-lite"
DEFAULT_DOCKER_NETWORK = "host"
DEFAULT_CORES_PER_AUTOTEST = 3
DEFAULT_AUTOTEST_JOBS = 2
DEFAULT_AUTOTEST_BATCH_SIZE = 4
MINIMUM_CORES_PER_AUTOTEST = 3
AUTOTEST_LOG_TAIL_LINES = 200
STATUS_BAR_MIN_WIDTH = 10
STATUS_BAR_MAX_WIDTH = 28
STATUS_REFRESH_SECONDS = 0.2

ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_CYAN = "\x1b[36m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_RED = "\x1b[31m"
SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

READINESS_TIMEOUT_SECONDS = 30
READINESS_POLL_INTERVAL_SECONDS = 1
PROCESS_STOP_TIMEOUT_SECONDS = 10
DATAPLANE_SOCKET_PATH = Path("/run/yanet/dataplane.sock")
DEBUG_REPORT_PATH = Path("/tmp/yanet-dp.report")

AUXILIARY_CORE_OFFSET = 1
WORKER_CORE_OFFSET = 2
DEFAULT_WORKER_CORE_ID = 2
CORE_BOUND_STEPS = {
    "- memorize_counter_value:",
    "- diff_with_kept_counter_value:",
}

BUILD_SCRIPT = r"""
set -Eeuo pipefail
ulimit -c 0

action="$1"

project_uid="$(stat -c %u /project)"
project_gid="$(stat -c %g /project)"

restore_ownership() {
    chown -R "${project_uid}:${project_gid}" \
        /project/build_unittest \
        /project/build_autotest 2>/dev/null || true
}
trap restore_ownership EXIT

apt-get update
apt-get install -y --no-install-recommends cmake

setup_build() {
    build_dir="$1"
    shift
    if [[ -f "${build_dir}/meson-private/coredata.dat" ]]; then
        meson setup --reconfigure "$@" "${build_dir}"
    else
        meson setup "$@" "${build_dir}"
    fi
}

case "${action}" in
    unit)
        echo "==> Building unit tests"
        setup_build build_unittest -Dtarget=unittest
        meson compile -C build_unittest
        echo "==> Running unit tests"
        meson test --no-rebuild -C build_unittest --print-errorlogs
        ;;
    autotest-build)
        echo "==> Building autotests"
        setup_build build_autotest -Dtarget=autotest -Dstrip=true
        meson compile -C build_autotest
        ;;
esac
"""


Command: TypeAlias = Sequence[str | Path]
BatchPhase: TypeAlias = Literal["batch", "retry"]
BuilderAction: TypeAlias = Literal["unit", "autotest-build"]
SuiteName: TypeAlias = Literal["all", "unit", "autotest"]
ReadinessProbe: TypeAlias = Callable[[], bool]
OutputKind: TypeAlias = Literal["info", "run", "pass", "warn", "fail"]


OUTPUT_MARKERS: dict[OutputKind, str] = {
    "info": "INFO",
    "run": "RUN",
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
}
OUTPUT_COLORS: dict[OutputKind, str] = {
    "info": ANSI_CYAN,
    "run": ANSI_CYAN,
    "pass": ANSI_GREEN,
    "warn": ANSI_YELLOW,
    "fail": ANSI_RED,
}


def print_event(
    kind: OutputKind,
    message: str,
    *,
    stream: TextIO | None = None,
) -> None:
    """Print a consistently formatted event, with color only on terminals."""
    output_stream = sys.stdout if stream is None else stream
    marker = f"[{OUTPUT_MARKERS[kind]:^4}]"
    if output_stream.isatty():
        marker = f"{ANSI_BOLD}{OUTPUT_COLORS[kind]}{marker}{ANSI_RESET}"
    print(f"{marker} {message}", file=output_stream, flush=True)


def print_section(
    title: str,
    details: Sequence[str],
    *,
    stream: TextIO | None = None,
) -> None:
    """Print a compact heading followed by aligned execution details."""
    output_stream = sys.stdout if stream is None else stream
    heading = f"── {title} " + "─" * max(3, 52 - len(title))
    if output_stream.isatty():
        heading = f"{ANSI_BOLD}{ANSI_CYAN}{heading}{ANSI_RESET}"
    print(heading, file=output_stream)
    for detail in details:
        print(f"   {detail}", file=output_stream)


def count_label(count: int, singular: str, plural: str | None = None) -> str:
    """Return a count with the grammatically appropriate noun form."""
    noun = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {noun}"


class CoreLayout(NamedTuple):
    """CPU IDs assigned to one isolated dataplane instance."""

    control_plane: int
    auxiliary: int
    worker: int


class ContainerRunner(Protocol):
    """Minimal container interface used by test orchestration."""

    container_prefix: str

    def run_container(
        self,
        arguments: Sequence[str],
        *,
        output_file: TextIO | None = None,
    ) -> int:
        """Run a container command and return its exit status."""
        ...


class TestRunnerError(RuntimeError):
    """Base exception for expected test-runner failures."""

    pass


class ReadinessError(TestRunnerError):
    """Raised when a service does not become ready in time."""

    pass


class AutotestFailed(TestRunnerError):
    """Raised when the autotest executable returns a failure status."""

    pass


class ServiceStopped(TestRunnerError):
    """Raised when a required service exits during an autotest."""

    pass


def positive_argument_integer(value: str) -> int:
    """Parse a positive integer for an argparse option."""
    try:
        parsed_value = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed_value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed_value


def command_text(command: Command) -> str:
    """Render a command in a shell-readable form for diagnostics."""
    return shlex.join(str(argument) for argument in command)


def run_command(
    command: Command,
    *,
    cwd: Path | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command synchronously without invoking a shell."""
    return subprocess.run(
        [str(argument) for argument in command],
        cwd=cwd,
        check=False,
        text=True,
        capture_output=capture_output,
    )


@dataclass(frozen=True, slots=True)
class AutotestOptions:
    """Command-line configuration for local autotest scheduling."""

    jobs: int = DEFAULT_AUTOTEST_JOBS
    batch_size: int = DEFAULT_AUTOTEST_BATCH_SIZE
    cores_per_worker: int = DEFAULT_CORES_PER_AUTOTEST
    pattern: str = "*"
    group: Path = DEFAULT_AUTOTEST_GROUP

    def __post_init__(self) -> None:
        """Validate the CPU spacing required by each dataplane instance."""
        if self.cores_per_worker < MINIMUM_CORES_PER_AUTOTEST:
            raise TestRunnerError(
                "cores per autotest must be at least "
                f"{MINIMUM_CORES_PER_AUTOTEST}"
            )

    @classmethod
    def from_arguments(cls, arguments: argparse.Namespace) -> "AutotestOptions":
        """Create autotest options from a fully defaulted CLI namespace."""
        return cls(
            jobs=arguments.jobs,
            batch_size=arguments.batch_size,
            cores_per_worker=arguments.cores_per_autotest,
            pattern=arguments.pattern,
            group=arguments.autotest_group,
        )


@dataclass(frozen=True, slots=True)
class LocalSettings:
    """Configuration for building and running local Docker test suites."""

    repository_root: Path
    builder_image: str = DEFAULT_BUILDER_IMAGE
    docker_network: str = DEFAULT_DOCKER_NETWORK
    autotest: AutotestOptions = field(default_factory=AutotestOptions)

    @classmethod
    def from_arguments(
        cls,
        repository_root: Path,
        suite: SuiteName,
        arguments: argparse.Namespace,
    ) -> "LocalSettings":
        """Create local settings exclusively from parsed CLI arguments."""
        autotest = (
            AutotestOptions()
            if suite == "unit"
            else AutotestOptions.from_arguments(arguments)
        )
        return cls(
            repository_root=repository_root,
            builder_image=arguments.builder_image,
            docker_network=arguments.docker_network,
            autotest=autotest,
        )


@dataclass(frozen=True, slots=True)
class AutotestBatch:
    """An immutable group of fixtures sharing one worker container."""

    identifier: int
    units: tuple[Path, ...]
    phase: BatchPhase = "batch"

    @property
    def label(self) -> str:
        """Return a compact label for logs and failure summaries."""
        if len(self.units) == 1:
            return self.units[0].name
        return f"{self.units[0].name}..{self.units[-1].name}"


@dataclass(frozen=True, slots=True)
class BatchResult:
    """Exit status and diagnostic log produced by one batch."""

    batch: AutotestBatch
    exit_code: int
    log_path: Path

    @property
    def passed(self) -> bool:
        """Report whether the batch command exited successfully."""
        return self.exit_code == 0


@dataclass(frozen=True, slots=True)
class AutotestResults:
    """Final failed units and initially failed shared batches."""

    failed_units: tuple[str, ...]
    failed_batches: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Report whether no unit or shared batch failed."""
        return not self.failed_units and not self.failed_batches


@dataclass(slots=True)
class ProgressState:
    """Mutable counters displayed while a group of batches executes."""

    phase: BatchPhase
    total_batches: int
    total_units: int
    completed_batches: int = 0
    completed_units: int = 0
    passed_units: int = 0
    failed_attempt_units: int = 0
    running_labels: set[str] = field(default_factory=set)
    started_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    """Options controlling an in-system dataplane/autotest runtime."""

    debug: bool = False
    keep: bool = False
    prefix: str = ""
    gdb_dataplane: bool = False
    gdb_controlplane: bool = False


@dataclass(frozen=True, slots=True)
class RuntimeBinaries:
    """Executable paths used by one direct autotest runtime."""

    dataplane: str = "yanet-dataplane"
    controlplane: str = "yanet-controlplane"
    cli: str = "yanet-cli"
    autotest: str = "yanet-autotest"

    @classmethod
    def from_prefix(cls, prefix: str) -> "RuntimeBinaries":
        """Resolve executable paths from the legacy optional prefix."""
        if not prefix:
            return cls()
        root = Path(prefix)
        return cls(
            dataplane=str(root / "dataplane" / "yanet-dataplane"),
            controlplane=str(root / "controlplane" / "yanet-controlplane"),
            cli=str(root / "cli" / "yanet-cli"),
            autotest=str(root / "autotest" / "yanet-autotest"),
        )


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    """Typed fixture selection and process settings for a direct run."""

    settings: RuntimeSettings
    units_group: Path
    units: tuple[Path, ...]

    @classmethod
    def from_arguments(cls, arguments: argparse.Namespace) -> "RuntimeRequest":
        """Convert an argparse namespace at the CLI boundary into typed data."""
        return cls(
            settings=RuntimeSettings(
                debug=arguments.debug,
                keep=arguments.keep,
                prefix=arguments.prefix,
                gdb_dataplane=arguments.gdb_dataplane,
                gdb_controlplane=arguments.gdb_controlplane,
            ),
            units_group=arguments.units_group,
            units=tuple(arguments.units),
        )


class DockerClient:
    """Small Docker CLI adapter with scoped worker cleanup."""

    def __init__(
        self,
        command_prefix: Sequence[str],
        container_prefix: str,
    ) -> None:
        """Initialize a Docker adapter for one repository invocation."""
        self.command_prefix = tuple(command_prefix)
        self.container_prefix = container_prefix

    @classmethod
    def discover(cls, repository_root: Path) -> "DockerClient":
        """Locate an accessible Docker command and create a scoped client."""
        if shutil.which("docker") is None:
            raise TestRunnerError("docker is required")

        command_prefix: tuple[str, ...] = ("docker",)
        if run_command([*command_prefix, "info"], capture_output=True).returncode:
            sudo_command = ("sudo", "-n", "docker")
            sudo_available = shutil.which("sudo") is not None
            if not sudo_available or run_command(
                [*sudo_command, "info"],
                capture_output=True,
            ).returncode:
                raise TestRunnerError(
                    "cannot access the Docker daemon "
                    "(add your user to the docker group or run 'sudo -v')"
                )
            command_prefix = sudo_command

        repository_id = zlib.crc32(str(repository_root).encode())
        container_prefix = (
            f"yanet-tests-{os.getuid()}-{repository_id}-{os.getpid()}"
        )
        return cls(command_prefix, container_prefix)

    def run_container(
        self,
        arguments: Sequence[str],
        *,
        output_file: TextIO | None = None,
    ) -> int:
        """Run one container, optionally redirecting combined output."""
        command = [*self.command_prefix, *arguments]
        process = subprocess.Popen(
            command,
            stdout=output_file,
            stderr=subprocess.STDOUT if output_file else None,
            text=True,
        )
        return process.wait()

    def stop_test_containers(self) -> None:
        """Stop containers whose names belong to this runner invocation."""
        result = run_command(
            [
                *self.command_prefix,
                "ps",
                "-aq",
                "--filter",
                f"name={self.container_prefix}",
            ],
            capture_output=True,
        )
        container_ids = result.stdout.split()
        if not container_ids:
            return
        run_command(
            [
                *self.command_prefix,
                "stop",
                "--timeout",
                str(PROCESS_STOP_TIMEOUT_SECONDS),
                *container_ids,
            ],
            capture_output=True,
        )


class IsolatedFixtureBuilder:
    """Copy fixtures and remap their core-bound configuration."""

    def __init__(self, source_group: Path, output_group: Path) -> None:
        """Configure source and destination fixture groups."""
        self.source_group = source_group
        self.output_group = output_group

    def prepare(self, source_units: Sequence[Path], core_base: int) -> list[Path]:
        """Create an isolated fixture group using a contiguous core layout."""
        self.output_group.mkdir(parents=True, exist_ok=True)
        self._prepare_dataplane_config(core_base)
        return [self._copy_unit(unit, core_base) for unit in source_units]

    def _prepare_dataplane_config(self, core_base: int) -> None:
        """Write a dataplane configuration remapped to the assigned cores."""
        source_path = self.source_group / "dataplane.conf"
        output_path = self.output_group / "dataplane.conf"
        with source_path.open(encoding="utf-8") as source_file:
            config = json.load(source_file)

        cores = CoreLayout(
            control_plane=core_base,
            auxiliary=core_base + AUXILIARY_CORE_OFFSET,
            worker=core_base + WORKER_CORE_OFFSET,
        )
        config["controlPlaneCoreId"] = cores.control_plane
        config["workerGC"] = [cores.auxiliary]
        config["dumpKniCoreId"] = cores.auxiliary
        for port in config["ports"]:
            port["coreIds"] = [cores.worker]

        with output_path.open("w", encoding="utf-8") as output_file:
            json.dump(config, output_file)

    def _copy_unit(self, source_unit: Path, core_base: int) -> Path:
        """Copy one fixture and rewrite its worker-core references."""
        output_unit = self.output_group / "units" / source_unit.name
        shutil.copytree(source_unit, output_unit)
        self._rewrite_autotest_yaml(
            output_unit / "autotest.yaml",
            core_base + WORKER_CORE_OFFSET,
        )
        return output_unit

    def _rewrite_autotest_yaml(
        self,
        yaml_path: Path,
        worker_core_id: int,
    ) -> None:
        """Rewrite shared-memory and counter references for one worker core."""
        source_lines = yaml_path.read_text(encoding="utf-8").splitlines(
            keepends=True
        )
        source_prefix = f"shm_{DEFAULT_WORKER_CORE_ID}_"
        target_prefix = f"shm_{worker_core_id}_"
        rewritten_lines: list[str] = []
        expects_counter_arguments = False

        for line_number, source_line in enumerate(source_lines, start=1):
            line = source_line.replace(source_prefix, target_prefix)
            stripped_line = line.strip()
            if stripped_line in CORE_BOUND_STEPS:
                expects_counter_arguments = True
            elif expects_counter_arguments and line[:1].isspace() and stripped_line:
                line = self._replace_counter_core(
                    line,
                    worker_core_id,
                    line_number,
                )
                expects_counter_arguments = False
            elif stripped_line:
                expects_counter_arguments = False
            rewritten_lines.append(line)

        yaml_path.write_text("".join(rewritten_lines), encoding="utf-8")

    @staticmethod
    def _replace_counter_core(
        line: str,
        worker_core_id: int,
        line_number: int,
    ) -> str:
        """Replace the core field in a counter-step argument line."""
        indentation = line[: len(line) - len(line.lstrip())]
        fields = line.strip().split()
        if len(fields) < 2:
            raise TestRunnerError(
                f"autotest.yaml:{line_number}: counter step needs a core ID"
            )
        fields[1] = str(worker_core_id)
        line_ending = "\n" if line.endswith("\n") else ""
        return indentation + " ".join(fields) + line_ending


class AutotestRuntime:
    """Manage dataplane, controlplane, and autotest process lifecycles."""

    def __init__(self, settings: RuntimeSettings) -> None:
        """Initialize a runtime from immutable process settings."""
        self.debug = settings.debug
        self.keep = settings.keep
        self.gdb_dataplane = settings.gdb_dataplane
        self.gdb_controlplane = settings.gdb_controlplane
        self.binaries = RuntimeBinaries.from_prefix(settings.prefix)
        self.child_environment = self._child_environment(settings.prefix)
        self.processes: list[subprocess.Popen[str]] = []

    @staticmethod
    def _child_environment(prefix: str) -> dict[str, str] | None:
        """Expose prefixed tools to shell commands spawned by yanet-autotest."""
        if not prefix:
            return None
        environment = os.environ.copy()
        binary_directories = [
            str(Path(prefix) / application)
            for application in ("dataplane", "controlplane", "cli", "autotest")
        ]
        current_path = environment.get("PATH")
        path_entries = [current_path, *binary_directories]
        environment["PATH"] = os.pathsep.join(
            entry for entry in path_entries if entry
        )
        return environment

    def run(self, dataplane_config: Path, units: Sequence[Path]) -> None:
        """Run fixtures against managed dataplane and controlplane services."""
        Path("/run/yanet").mkdir(parents=True, exist_ok=True)
        try:
            dataplane = self._start_dataplane(dataplane_config)
            self._wait_for_application(
                "dataplane",
                dataplane,
                self.gdb_dataplane,
            )
            self._wait_for_path(
                DATAPLANE_SOCKET_PATH,
                "dataplane socket",
                dataplane,
                self.gdb_dataplane,
            )

            controlplane = self._start_controlplane()
            self._wait_for_application(
                "controlplane",
                controlplane,
                self.gdb_controlplane,
            )
            autotest = self._start_process(
                [self.binaries.autotest, *(str(unit) for unit in units)]
            )

            if self.keep:
                for process in (autotest, controlplane, dataplane):
                    process.wait()
                return

            autotest.wait()
            if autotest.returncode:
                self._print_debug_report()
                raise AutotestFailed(
                    f"yanet-autotest exited with status {autotest.returncode}"
                )
            if dataplane.poll() is not None or controlplane.poll() is not None:
                self._print_debug_report()
                raise ServiceStopped(
                    "dataplane or controlplane stopped before the autotest completed"
                )
        finally:
            self.stop()

    def _start_dataplane(self, config_path: Path) -> subprocess.Popen[str]:
        """Start the dataplane process and return its process handle."""
        command = [self.binaries.dataplane, "-c", str(config_path)]
        if self.gdb_dataplane:
            command = ["gdb", "--args", *command]
        if self.debug:
            command.append("-d")
        return self._start_process(command)

    def _start_controlplane(self) -> subprocess.Popen[str]:
        """Start the controlplane process and return its process handle."""
        command = [self.binaries.controlplane]
        if self.gdb_controlplane:
            command = ["gdb", "--args", *command]
        if self.debug:
            command.append("-d")
        return self._start_process(command)

    def _start_process(
        self,
        command: Sequence[str],
    ) -> subprocess.Popen[str]:
        """Start and track a child process for deterministic cleanup."""
        if self.debug:
            print(f"DEBUG: Executing command: {command_text(command)}")
        process = subprocess.Popen(
            [str(argument) for argument in command],
            env=self.child_environment,
            text=True,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def _wait_for_application(
        self,
        application: str,
        process: subprocess.Popen[str],
        gdb_enabled: bool,
    ) -> None:
        """Wait until yanet-cli reports an application as available."""
        def application_is_ready() -> bool:
            """Probe yanet-cli for the requested application name."""
            try:
                result = subprocess.run(
                    [self.binaries.cli, "version"],
                    env=self.child_environment,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                return False
            return result.returncode == 0 and application in result.stdout

        self._wait_until_ready(
            application_is_ready,
            f"application: {application}",
            process,
            gdb_enabled,
        )

    def _wait_for_path(
        self,
        path: Path,
        description: str,
        process: subprocess.Popen[str],
        gdb_enabled: bool,
    ) -> None:
        """Wait until a service-owned filesystem path exists."""
        self._wait_until_ready(
            path.exists,
            f"{description}: {path}",
            process,
            gdb_enabled,
        )

    @staticmethod
    def _wait_until_ready(
        is_ready: ReadinessProbe,
        description: str,
        process: subprocess.Popen[str],
        gdb_enabled: bool,
    ) -> None:
        """Poll a readiness probe while detecting timeout or early exit."""
        deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
        while not is_ready():
            if not gdb_enabled and process.poll() is not None:
                raise ReadinessError(
                    f"process stopped while waiting for {description}"
                )
            if not gdb_enabled and time.monotonic() >= deadline:
                raise ReadinessError(f"timed out waiting for {description}")
            time.sleep(READINESS_POLL_INTERVAL_SECONDS)

    def _print_debug_report(self) -> None:
        """Print the dataplane report when debug diagnostics are enabled."""
        if self.debug and DEBUG_REPORT_PATH.exists():
            print(DEBUG_REPORT_PATH.read_text(encoding="utf-8", errors="replace"))

    def stop(self) -> None:
        """Stop all tracked processes in reverse startup order."""
        for process in reversed(self.processes):
            self._stop_process(process)
        self.processes.clear()

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> None:
        """Terminate one process group, escalating to SIGKILL on timeout."""
        if process.poll() is not None:
            return
        try:
            process_group = os.getpgid(process.pid)
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process_group, signal.SIGKILL)
            process.wait()


class TestStatusBar:
    """Render thread-safe batch progress for terminals and CI logs."""

    def __init__(
        self,
        batches: Sequence[AutotestBatch],
        stream: TextIO,
    ) -> None:
        """Initialize progress counters from a non-empty batch sequence."""
        self.stream = stream
        self.interactive = stream.isatty()
        self.state = ProgressState(
            phase=batches[0].phase,
            total_batches=len(batches),
            total_units=sum(len(batch.units) for batch in batches),
        )
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Display initial progress and start interactive refreshes."""
        with self._lock:
            self._render_locked()
        if self.interactive:
            self._thread = threading.Thread(
                target=self._refresh_loop,
                name="yanet-test-status",
                daemon=True,
            )
            self._thread.start()

    def mark_started(self, batch: AutotestBatch) -> None:
        """Mark a batch as running after it acquires a CPU slot."""
        with self._lock:
            self.state.running_labels.add(batch.label)
            if self.interactive:
                self._render_locked()
            else:
                phase = "retry" if batch.phase == "retry" else "batch"
                print_event(
                    "run",
                    f"{phase} {batch.identifier:03d} · "
                    f"{count_label(len(batch.units), 'test')} · {batch.label}",
                    stream=self.stream,
                )

    def mark_completed(self, result: BatchResult) -> None:
        """Update progress counters from one completed batch attempt."""
        unit_count = len(result.batch.units)
        with self._lock:
            self.state.running_labels.discard(result.batch.label)
            self.state.completed_batches += 1
            self.state.completed_units += unit_count
            if result.passed:
                self.state.passed_units += unit_count
            else:
                self.state.failed_attempt_units += unit_count
            if not self.interactive:
                phase = "retry" if result.batch.phase == "retry" else "batch"
                detail = (
                    f"{phase} {result.batch.identifier:03d} · "
                    f"{count_label(unit_count, 'test')} · {result.batch.label}"
                )
                if not result.passed:
                    detail += f" · exit {result.exit_code}"
                print_event(
                    "pass" if result.passed else "fail",
                    detail,
                    stream=self.stream,
                )
            self._render_locked()

    def stop(self) -> None:
        """Stop refreshes and leave a final persistent status line."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        if self.interactive:
            with self._lock:
                self._render_locked(finish_line=True)

    def _refresh_loop(self) -> None:
        """Refresh elapsed time until execution completes."""
        while not self._stop_event.wait(STATUS_REFRESH_SECONDS):
            with self._lock:
                self._render_locked()

    def _render_locked(self, *, finish_line: bool = False) -> None:
        """Render state while the caller holds the progress lock."""
        if self.interactive:
            terminal_width = shutil.get_terminal_size((120, 20)).columns
            status = self._status_text_locked(
                terminal_width=terminal_width,
                include_active_labels=terminal_width >= 120,
                finished=finish_line,
            )
            status = status[: max(1, terminal_width - 1)]
            if finish_line:
                color = (
                    ANSI_GREEN
                    if self.state.failed_attempt_units == 0
                    else ANSI_RED
                )
            else:
                color = ANSI_CYAN
            ending = "\n" if finish_line else ""
            self.stream.write(
                f"\r\x1b[2K{ANSI_BOLD}{color}{status}{ANSI_RESET}{ending}"
            )
        else:
            self.stream.write(f"[PROGRESS] {self._log_text_locked()}\n")
        self.stream.flush()

    def _log_text_locked(self) -> str:
        """Format a stable ASCII progress checkpoint for redirected output."""
        state = self.state
        queued_batches = max(
            0,
            state.total_batches
            - state.completed_batches
            - len(state.running_labels),
        )
        elapsed = self._format_elapsed(time.monotonic() - state.started_at)
        if state.phase == "retry":
            phase = "retry" if state.total_batches == 1 else "retries"
        else:
            phase = "batch" if state.total_batches == 1 else "batches"
        return (
            f"{state.completed_batches}/{state.total_batches} {phase} · "
            f"{state.completed_units}/{state.total_units} tests · "
            f"pass {state.passed_units} · fail {state.failed_attempt_units} · "
            f"running {len(state.running_labels)} · queued {queued_batches} · "
            f"{elapsed}"
        )

    def _status_text_locked(
        self,
        *,
        terminal_width: int,
        include_active_labels: bool,
        finished: bool,
    ) -> str:
        """Format one progress snapshot while holding the progress lock."""
        state = self.state
        completed_ratio = state.completed_units / state.total_units
        percentage = round(completed_ratio * 100)
        bar_width = min(
            STATUS_BAR_MAX_WIDTH,
            max(STATUS_BAR_MIN_WIDTH, terminal_width - 88),
        )
        filled_width = round(completed_ratio * bar_width)
        bar = "█" * filled_width + "░" * (bar_width - filled_width)
        queued_batches = max(
            0,
            state.total_batches
            - state.completed_batches
            - len(state.running_labels),
        )
        elapsed = self._format_elapsed(time.monotonic() - state.started_at)
        phase = "RETRIES" if state.phase == "retry" else "AUTOTESTS"
        if finished:
            activity = "✓" if state.failed_attempt_units == 0 else "!"
        else:
            frame_index = int(
                (time.monotonic() - state.started_at) / STATUS_REFRESH_SECONDS
            )
            activity = SPINNER_FRAMES[frame_index % len(SPINNER_FRAMES)]
        if terminal_width < 88:
            status = (
                f"{activity} {phase} [{bar}] {state.completed_units}/"
                f"{state.total_units} · {percentage:3d}% · {elapsed}"
            )
        else:
            status = (
                f"{activity} {phase} [{bar}] {state.completed_units}/"
                f"{state.total_units} · {percentage:3d}%  "
                f"✓ {state.passed_units}  ✗ {state.failed_attempt_units}  "
                f"▶ {len(state.running_labels)}  … {queued_batches}  {elapsed}"
            )
        if include_active_labels and state.running_labels:
            status += f"  ·  {self._running_text_locked()}"
        return status

    def _running_text_locked(self) -> str:
        """Format a bounded list of running batch labels."""
        labels = sorted(self.state.running_labels)
        if not labels:
            return "idle"
        visible_labels = labels[:2]
        suffix = f" +{len(labels) - 2}" if len(labels) > 2 else ""
        return f"active: {', '.join(visible_labels)}{suffix}"

    @staticmethod
    def _format_elapsed(elapsed_seconds: float) -> str:
        """Format elapsed seconds as a compact clock duration."""
        minutes, seconds = divmod(int(elapsed_seconds), 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"


class AutotestPool:
    """Schedule memory-bounded fixture batches across Docker workers."""

    def __init__(
        self,
        docker: ContainerRunner,
        settings: LocalSettings,
        log_directory: Path,
    ) -> None:
        """Initialize batching, logging, and exclusive CPU-slot allocation."""
        self.docker = docker
        self.settings = settings
        self.log_directory = log_directory
        self.core_slots: queue.Queue[int] = queue.Queue()
        for slot in range(settings.autotest.jobs):
            self.core_slots.put(slot)

    def run(self, units: Sequence[Path]) -> AutotestResults:
        """Run initial batches and isolate units from every failed batch."""
        initial_batches = self._make_batches(units)
        worker_count = min(
            self.settings.autotest.jobs,
            len(initial_batches),
        )
        print_section(
            "YANET autotests",
            (
                f"{count_label(len(units), 'test')} · "
                f"{count_label(len(initial_batches), 'batch')} · "
                f"{count_label(worker_count, 'worker')}",
                f"{count_label(self.settings.autotest.batch_size, 'test')} "
                f"per batch · "
                f"{count_label(self.settings.autotest.cores_per_worker, 'core')} "
                "per worker",
                f"Logs: {self.log_directory}",
            ),
        )

        initial_results = self._execute(initial_batches)
        failed_units: list[str] = []
        failed_batches: list[str] = []
        retry_units: list[Path] = []

        for result in initial_results:
            if result.passed:
                continue
            if len(result.batch.units) == 1:
                failed_units.append(result.batch.units[0].name)
                self._print_failure(result, result.batch.units[0].name)
            else:
                failed_batches.append(result.batch.label)
                retry_units.extend(result.batch.units)
                self._print_batch_failure(result)

        if retry_units:
            print_section(
                "Isolated retries",
                (
                    f"Rerunning {count_label(len(retry_units), 'test')} "
                    "from failed batches",
                    "Each retry uses a fresh container",
                ),
            )
            retry_start = len(initial_batches) + 1
            retry_batches = [
                AutotestBatch(
                    identifier=retry_start + index,
                    units=(unit,),
                    phase="retry",
                )
                for index, unit in enumerate(retry_units)
            ]
            for result in self._execute(retry_batches):
                unit_name = result.batch.units[0].name
                if result.passed and sys.stdout.isatty():
                    print_event("pass", f"retry · {unit_name}")
                elif not result.passed:
                    failed_units.append(unit_name)
                    self._print_failure(result, unit_name)

        return AutotestResults(
            tuple(failed_units),
            tuple(failed_batches),
        )

    def _make_batches(self, units: Sequence[Path]) -> list[AutotestBatch]:
        """Partition selected fixtures into immutable fixed-size batches."""
        batch_size = self.settings.autotest.batch_size
        return [
            AutotestBatch(
                identifier=index // batch_size + 1,
                units=tuple(units[index : index + batch_size]),
            )
            for index in range(0, len(units), batch_size)
        ]

    def _execute(self, batches: Sequence[AutotestBatch]) -> list[BatchResult]:
        """Execute batches concurrently up to the configured worker limit."""
        if not batches:
            return []
        worker_count = min(self.settings.autotest.jobs, len(batches))
        results: list[BatchResult] = []
        status_bar = TestStatusBar(batches, sys.stdout)
        status_bar.start()
        try:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = [
                    executor.submit(
                        self._run_with_core_slot,
                        batch,
                        status_bar,
                    )
                    for batch in batches
                ]
                for future in as_completed(futures):
                    results.append(future.result())
        finally:
            status_bar.stop()
        return results

    def _run_with_core_slot(
        self,
        batch: AutotestBatch,
        status_bar: TestStatusBar,
    ) -> BatchResult:
        """Run one batch while holding an exclusive contiguous core slot."""
        slot = self.core_slots.get()
        try:
            status_bar.mark_started(batch)
            result = self._run_batch(batch, slot)
            status_bar.mark_completed(result)
            return result
        finally:
            self.core_slots.put(slot)

    def _run_batch(self, batch: AutotestBatch, slot: int) -> BatchResult:
        """Execute one fixture batch in a fresh isolated container."""
        log_path = self._log_path(batch)
        container_name = (
            f"{self.docker.container_prefix}-autotest-"
            f"{batch.phase}-{batch.identifier:03d}"
        )
        core_base = slot * self.settings.autotest.cores_per_worker
        arguments = [
            "run",
            "--rm",
            "--init",
            "--ulimit",
            "core=0",
            "--volume",
            f"{self.settings.repository_root}:/project",
            "--workdir",
            "/project",
            "--network",
            "none",
            "--name",
            container_name,
            self.settings.builder_image,
            "./run-tests.py",
            "isolated-autotest-runner",
            "--prefix",
            "build_autotest",
            "--core-base",
            str(core_base),
            "--source-group",
            self.settings.autotest.group.as_posix(),
            *(unit.as_posix() for unit in batch.units),
        ]

        with log_path.open("w", encoding="utf-8") as log_file:
            try:
                exit_code = self.docker.run_container(
                    arguments,
                    output_file=log_file,
                )
            except OSError as error:
                print(f"failed to start container: {error}", file=log_file)
                exit_code = 127
        return BatchResult(batch, exit_code, log_path)

    def _log_path(self, batch: AutotestBatch) -> Path:
        """Return the deterministic log path for a batch attempt."""
        filename = f"{batch.phase}-{batch.identifier:03d}-{batch.units[0].name}.log"
        return self.log_directory / filename

    def _print_batch_failure(self, result: BatchResult) -> None:
        """Report a failed shared batch before scheduling isolation retries."""
        print_event(
            "warn",
            f"batch {result.batch.label} exited {result.exit_code}; "
            f"scheduling isolated retries · {result.log_path}",
            stream=sys.stderr,
        )
        self._print_log_tail(result.log_path)

    def _print_failure(self, result: BatchResult, unit_name: str) -> None:
        """Report a fixture proven to fail in its own fresh container."""
        print_event(
            "fail",
            f"{unit_name} · exit {result.exit_code} · {result.log_path}",
            stream=sys.stderr,
        )
        self._print_log_tail(result.log_path)

    @staticmethod
    def _print_log_tail(log_path: Path) -> None:
        """Print the bounded diagnostic tail of a worker log."""
        lines = log_path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        for line in lines[-AUTOTEST_LOG_TAIL_LINES:]:
            print(line, file=sys.stderr)


class LocalTestRunner:
    """Coordinate local builds and memory-bounded test execution."""

    def __init__(
        self,
        settings: LocalSettings,
        docker: ContainerRunner,
    ) -> None:
        """Initialize the local suite runner and its container collaborator."""
        self.settings = settings
        self.docker = docker

    def run_unit_tests(self) -> int:
        """Build and run the Meson unit-test suite in Docker."""
        print_section(
            "YANET unit tests",
            (f"Builder: {self.settings.builder_image}",),
        )
        return self._run_builder_action("unit")

    def run_autotests(self) -> int:
        """Build, select, batch, and run local autotest fixtures."""
        cpu_count = os.cpu_count() or 1
        required_cpus = (
            self.settings.autotest.jobs
            * self.settings.autotest.cores_per_worker
        )
        if required_cpus > cpu_count:
            raise TestRunnerError(
                f"{self.settings.autotest.jobs} autotest jobs require CPU IDs "
                f"0-{required_cpus - 1}; {cpu_count} CPUs are available"
            )

        print_event(
            "info",
            f"Building autotest binaries with {self.settings.builder_image}",
        )
        build_status = self._run_builder_action("autotest-build")
        if build_status:
            return build_status

        units = self._selected_autotest_units()
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        log_directory = (
            self.settings.repository_root
            / "build_autotest"
            / "parallel-logs"
            / f"{timestamp}-{os.getpid()}"
        )
        log_directory.mkdir(parents=True, exist_ok=True)
        results = AutotestPool(
            self.docker,
            self.settings,
            log_directory,
        ).run(units)

        if not self._report_autotest_results(results):
            return 1

        print_event("pass", f"All {count_label(len(units), 'autotest')} passed")
        return 0

    @staticmethod
    def _report_autotest_results(results: AutotestResults) -> bool:
        """Print failure summaries and return the aggregate pass state."""
        if results.failed_units:
            print_event(
                "fail",
                f"{count_label(len(results.failed_units), 'autotest')}: "
                f"{', '.join(results.failed_units)}",
                stream=sys.stderr,
            )
        if results.failed_batches:
            failed_batch_count = count_label(
                len(results.failed_batches),
                "initial batch",
                "initial batches",
            )
            print_event(
                "warn",
                f"{failed_batch_count}: {', '.join(results.failed_batches)}",
                stream=sys.stderr,
            )
        return results.passed

    def run_all_tests(self) -> int:
        """Run unit tests and autotests sequentially to bound peak memory."""
        unit_status = self.run_unit_tests()
        autotest_status = self.run_autotests()
        if unit_status or autotest_status:
            print_event(
                "fail",
                f"Suite summary · unit={unit_status} · "
                f"autotest={autotest_status}",
                stream=sys.stderr,
            )
            return 1
        return 0

    def _run_builder_action(self, action: BuilderAction) -> int:
        """Execute a validated build action in the configured builder image."""
        container_name = f"{self.docker.container_prefix}-{action}"
        arguments = [
            "run",
            "--rm",
            "--init",
            "--volume",
            f"{self.settings.repository_root}:/project",
            "--workdir",
            "/project",
        ]
        if self.settings.docker_network:
            arguments.extend(["--network", self.settings.docker_network])
        arguments.extend(
            [
                "--name",
                container_name,
                self.settings.builder_image,
                "bash",
                "-lc",
                BUILD_SCRIPT,
                "yanet-build",
                action,
            ]
        )
        return self.docker.run_container(arguments)

    def _selected_autotest_units(self) -> list[Path]:
        """Discover fixture directories matching the configured name pattern."""
        group_path = (
            self.settings.repository_root / self.settings.autotest.group
        )
        candidates = sorted(
            path
            for path in group_path.iterdir()
            if path.is_dir() and path.name != "disabled"
        )
        selected_units = [
            self.settings.autotest.group / candidate.name
            for candidate in candidates
            if fnmatch.fnmatchcase(
                candidate.name,
                self.settings.autotest.pattern,
            )
        ]
        if not selected_units:
            raise TestRunnerError(
                f"no autotests in {self.settings.autotest.group} match "
                f"{self.settings.autotest.pattern}"
            )
        return selected_units


def prepare_repository(repository_root: Path) -> None:
    """Validate submodule state and initialize only missing submodules."""
    if shutil.which("git") is None:
        raise TestRunnerError("git is required")
    status = run_command(
        ["git", "submodule", "status", "--recursive"],
        cwd=repository_root,
        capture_output=True,
    )
    if status.returncode:
        raise TestRunnerError(status.stderr.strip() or "cannot inspect submodules")
    if any(line.startswith("-") for line in status.stdout.splitlines()):
        print_event("info", "Initializing missing git submodules")
        initialization = run_command(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=repository_root,
        )
        if initialization.returncode:
            raise TestRunnerError("failed to initialize git submodules")
    if any(line.startswith("U") for line in status.stdout.splitlines()):
        raise TestRunnerError("resolve conflicted git submodules before running tests")


def run_local_suite(
    suite: SuiteName,
    settings: LocalSettings,
) -> int:
    """Run a selected local Docker suite with scoped cleanup."""
    prepare_repository(settings.repository_root)
    docker = DockerClient.discover(settings.repository_root)
    runner = LocalTestRunner(settings, docker)
    try:
        if suite == "unit":
            status = runner.run_unit_tests()
        elif suite == "autotest":
            status = runner.run_autotests()
        else:
            status = runner.run_all_tests()
    finally:
        docker.stop_test_containers()

    if status == 0 and suite != "autotest":
        summary = (
            "Unit test suite passed"
            if suite == "unit"
            else "All requested YANET test suites passed"
        )
        print_event("pass", summary)
    return status


def selected_units(group: Path, requested_units: Sequence[Path]) -> list[Path]:
    """Return requested fixtures or discover every enabled group fixture."""
    if requested_units:
        return list(requested_units)
    return sorted(
        path
        for path in group.iterdir()
        if path.is_dir() and path.name != "disabled"
    )


def run_autotest_runtime(request: RuntimeRequest) -> int:
    """Execute one typed direct-runtime request and map failures to exit codes."""
    group = request.units_group
    units = selected_units(group, request.units)
    runtime = AutotestRuntime(request.settings)
    try:
        runtime.run(group / "dataplane.conf", units)
    except ReadinessError as error:
        print_event("fail", str(error), stream=sys.stderr)
        return 2
    except AutotestFailed:
        return 3
    except ServiceStopped as error:
        print_event("fail", str(error), stream=sys.stderr)
        return 4
    return 0


def run_isolated_autotest(arguments: argparse.Namespace) -> int:
    """Prepare remapped fixtures and run them in the current worker system."""
    fixture_builder = IsolatedFixtureBuilder(
        arguments.source_group,
        ISOLATED_GROUP,
    )
    isolated_units = fixture_builder.prepare(
        arguments.units,
        arguments.core_base,
    )
    runtime_request = RuntimeRequest(
        settings=RuntimeSettings(
            debug=arguments.debug,
            prefix=arguments.prefix,
        ),
        units_group=ISOLATED_GROUP,
        units=tuple(isolated_units),
    )
    return run_autotest_runtime(runtime_request)


def add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    """Add direct-runtime options and fixture paths to a subparser."""
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="enable debug mode",
    )
    parser.add_argument(
        "--gdb-dataplane",
        action="store_true",
        default=False,
        help="run dataplane with gdb",
    )
    parser.add_argument(
        "--gdb-controlplane",
        action="store_true",
        default=False,
        help="run controlplane with gdb",
    )
    parser.add_argument(
        "-k",
        "--keep",
        action="store_true",
        default=False,
        help="keep processes running after autotest",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="add a prefix for YANET binary paths",
    )
    parser.add_argument("units_group", type=Path)
    parser.add_argument("units", nargs="*", type=Path)


def add_local_build_arguments(parser: argparse.ArgumentParser) -> None:
    """Add builder-container options shared by every local suite."""
    parser.add_argument(
        "--builder-image",
        default=DEFAULT_BUILDER_IMAGE,
        help=f"builder image (default: {DEFAULT_BUILDER_IMAGE})",
    )
    parser.add_argument(
        "--docker-network",
        default=DEFAULT_DOCKER_NETWORK,
        help=f"builder container network (default: {DEFAULT_DOCKER_NETWORK})",
    )


def add_local_autotest_arguments(parser: argparse.ArgumentParser) -> None:
    """Add explicit local autotest selection and scheduling options."""
    parser.add_argument(
        "--jobs",
        type=positive_argument_integer,
        default=DEFAULT_AUTOTEST_JOBS,
        help=f"concurrent autotest containers (default: {DEFAULT_AUTOTEST_JOBS})",
    )
    parser.add_argument(
        "--batch-size",
        type=positive_argument_integer,
        default=DEFAULT_AUTOTEST_BATCH_SIZE,
        help=(
            "fixtures sharing one container "
            f"(default: {DEFAULT_AUTOTEST_BATCH_SIZE})"
        ),
    )
    parser.add_argument(
        "--cores-per-autotest",
        type=positive_argument_integer,
        default=DEFAULT_CORES_PER_AUTOTEST,
        help=(
            "CPU IDs reserved per concurrent container "
            f"(default: {DEFAULT_CORES_PER_AUTOTEST}, minimum: "
            f"{MINIMUM_CORES_PER_AUTOTEST})"
        ),
    )
    parser.add_argument(
        "--pattern",
        default="*",
        help="fixture-name glob (default: *)",
    )
    parser.add_argument(
        "--autotest-group",
        type=Path,
        default=DEFAULT_AUTOTEST_GROUP,
        help=f"fixture group (default: {DEFAULT_AUTOTEST_GROUP})",
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the complete command-line parser for every runner mode."""
    parser = argparse.ArgumentParser(
        description=(
            "Build and run YANET tests. Local suites use memory-bounded Docker "
            "batches; autotest-runner executes fixtures in the current system."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for suite in ("all", "unit", "autotest"):
        suite_parser = subparsers.add_parser(
            suite,
            help=f"run the {suite} test suite",
        )
        add_local_build_arguments(suite_parser)
        if suite != "unit":
            add_local_autotest_arguments(suite_parser)

    runtime_parser = subparsers.add_parser(
        "autotest-runner",
        help="run autotest fixtures without Docker orchestration",
    )
    add_runtime_arguments(runtime_parser)

    isolated_parser = subparsers.add_parser(
        "isolated-autotest-runner",
        help="run a core-remapped fixture batch inside a worker container",
    )
    isolated_parser.add_argument("-d", "--debug", action="store_true")
    isolated_parser.add_argument("--prefix", default="")
    isolated_parser.add_argument("--core-base", type=int, required=True)
    isolated_parser.add_argument("--source-group", type=Path, required=True)
    isolated_parser.add_argument("units", nargs="+", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, dispatch one runner mode, and return an exit code."""
    arguments_list = list(argv if argv is not None else sys.argv[1:])
    if not arguments_list:
        arguments_list = ["all"]
    arguments = build_argument_parser().parse_args(arguments_list)

    try:
        if arguments.command in {"all", "unit", "autotest"}:
            suite = cast(SuiteName, arguments.command)
            return run_local_suite(
                suite,
                LocalSettings.from_arguments(
                    REPOSITORY_ROOT,
                    suite,
                    arguments,
                ),
            )
        if arguments.command == "autotest-runner":
            return run_autotest_runtime(RuntimeRequest.from_arguments(arguments))
        return run_isolated_autotest(arguments)
    except TestRunnerError as error:
        print_event("fail", str(error), stream=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print_event("warn", "Interrupted", stream=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
