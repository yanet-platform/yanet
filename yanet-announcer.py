#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import functools
import json
import logging
import signal
import subprocess
import ipaddress
import textwrap
import time
import typing
from collections import abc

CONFIGURATION_PATH: str = "/etc/yanet/announcer.conf"
MACHINE_TARGET_PATH: str = "/etc/yanet/target"

ANNOUNCER_CONFIG: typing.Any = None
LOGGER: typing.Optional[logging.Logger] = None
OPTIONS: typing.Optional[argparse.Namespace] = None
SIGNAL_RECV: bool = False

SKIP_CHECKS_ALL_KEYWORD: str = "all"
SKIP_CHECKS_CONFIG_PARAM: str = "skip_checks"


class Decorator:
    """Class with static decorators."""

    @staticmethod
    def skip_function(return_value: typing.Any = None):
        """Decorator skips func execution for passed names in args."""

        def decorator(func: typing.Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if func.__name__ in OPTIONS.skip or SKIP_CHECKS_ALL_KEYWORD in OPTIONS.skip:
                    LOGGER.debug("skip func execution: %s", func.__name__)
                    return return_value
                return func(*args, **kwargs)

            return wrapper

        return decorator

    @staticmethod
    def logger_function(func: typing.Callable):
        """Decorator logs func args."""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if OPTIONS.dry_run:
                LOGGER.debug("func call %s(%s, %s)", func.__name__, args, kwargs)
            return func(*args, **kwargs)

        return wrapper


class Executer:
    """Class that allow to execute commands."""

    @staticmethod
    @functools.lru_cache(maxsize=128)
    def get(command: str) -> typing.List[typing.Dict[str, str]]:
        """Execute and parse output."""

        # don't use generator output, because LRU cache return wrong response
        parsed_output: typing.List[typing.Dict[str, str]] = []

        out = subprocess.check_output(command, shell=True).decode("ascii").splitlines()
        if len(out) <= 1:
            return parsed_output

        column_lengths: typing.List[int] = [len(column) for column in out[1].split("  ")]

        offset = 0
        headers = []
        for i in range(0, len(column_lengths)):
            headers.append(out[0][offset : offset + column_lengths[i]].strip())
            offset += column_lengths[i] + 2

        for row_i in range(2, len(out)):
            offset = 0
            columns: typing.Dict[str, str] = {}

            for i in range(0, len(column_lengths)):
                columns[headers[i]] = out[row_i][offset : offset + column_lengths[i]].strip()
                offset += column_lengths[i] + 2
            parsed_output.append(columns)

        return parsed_output

    @staticmethod
    def flush_cache() -> None:
        Executer.get.cache_clear()

    @staticmethod
    def run(command: str) -> int:
        """Execute and return exit code."""

        proc = subprocess.run(command, shell=True)
        return proc.returncode


def bgp_update_ipv4(prefix):
    LOGGER.info("bgp_update_ipv4: %s", prefix)
    if prefix not in ANNOUNCER_CONFIG:
        return

    for command in ANNOUNCER_CONFIG[prefix]["update"]:
        LOGGER.info(command)
        if not OPTIONS.dry_run:
            Executer.run(command)


def bgp_remove_ipv4(prefix):
    LOGGER.info("bgp_remove_ipv4: %s", prefix)
    if prefix not in ANNOUNCER_CONFIG:
        return

    for command in ANNOUNCER_CONFIG[prefix]["remove"]:
        LOGGER.info(command)
        if not OPTIONS.dry_run:
            Executer.run(command)


def bgp_update_ipv6(prefix):
    LOGGER.info("bgp_update_ipv6: %s", prefix)
    if prefix not in ANNOUNCER_CONFIG:
        return

    for command in ANNOUNCER_CONFIG[prefix]["update"]:
        LOGGER.info(command)
        if not OPTIONS.dry_run:
            Executer.run(command)


def bgp_remove_ipv6(prefix):
    LOGGER.info("bgp_remove_ipv6: %s", prefix)
    if prefix not in ANNOUNCER_CONFIG:
        return

    for command in ANNOUNCER_CONFIG[prefix]["remove"]:
        LOGGER.info(command)
        if not OPTIONS.dry_run:
            Executer.run(command)


def bgp_update(prefix_list):
    for prefix in prefix_list:
        try:
            parsed = ipaddress.ip_network(prefix)
            if parsed.version == 6:
                bgp_update_ipv6(prefix)
            else:
                bgp_update_ipv4(prefix)
        except Exception as error:
            LOGGER.error("Can not update bgp prefix: %s with error: %s", prefix, error)


def bgp_remove(prefix_list):
    for prefix in prefix_list:
        try:
            parsed = ipaddress.ip_network(prefix)
            if parsed.version == 6:
                bgp_remove_ipv6(prefix)
            else:
                bgp_remove_ipv4(prefix)
        except Exception as error:
            LOGGER.error("Can not remove bgp prefix: %s with error: %s", prefix, error)


def get_announces(types):
    for type in types:
        table_decap = Executer.get(f"yanet-cli {type}")
        table_decap_announce = Executer.get(f"yanet-cli {type} announce")

        for table_decap_row in table_decap:
            module = table_decap_row["module"]
            next_module = table_decap_row["next_module"]

            announces = []
            for table_decap_announce_row in table_decap_announce:
                if table_decap_announce_row["module"] != module:
                    continue

                if table_decap_announce_row["announces"] == "n/s":
                    continue

                announces.extend(table_decap_announce_row["announces"].split(","))

            yield {"module": module, "type": type, "announces": announces, "next_module": next_module}


@Decorator.logger_function
@Decorator.skip_function()
def check_services():
    # Example
    """
    ~ yanet-cli version
    application   version  revision  hash      custom
    ------------  -------  --------  --------  --------------
    dataplane     0.0      0         00000000  develop
    controlplane  0.0      0         00000000  develop
    cli           0.0      0         00000000  develop
    """
    LOGGER.info("Checking dataplane/contorlplane...")
    try:
        lines = Executer.get("/usr/bin/yanet-cli version")
        application = set()
        for line in lines:
            application.add(line.get("application"))
        if application != {"cli", "controlplane", "dataplane"}:
            raise Exception("main services(dataplane, controlplane) not running")
        LOGGER.info("Dataplane/controlplane is in running state!")
    except:
        raise Exception("Can not get version from yanet-cli.")


@Decorator.logger_function
@Decorator.skip_function()
def check_rib(rib_table: str) -> None:
    runtime_rib_table = Executer.get("yanet-cli rib")

    if len(runtime_rib_table) < 1:
        raise Exception(f"check_rib('{rib_table}')")

    for row in runtime_rib_table:
        if row["table_name"] == rib_table:
            return

    raise Exception(f"check_rib('{rib_table}')")


@Decorator.logger_function
@Decorator.skip_function()
def check_default_v4(route):
    interfaces = Executer.get("yanet-cli route interface")
    routes = Executer.get(f"yanet-cli route get {route} 0.0.0.0/0")

    for route_row in routes:
        for interface_row in interfaces:
            if interface_row["module"] != route:
                continue
            if route_row["egress_interface"] == interface_row["interface"]:
                return

    raise Exception(f"check_default_v4('{route}')")


@Decorator.logger_function
@Decorator.skip_function()
def check_default_v6(route):
    interfaces = Executer.get("yanet-cli route interface")
    routes = Executer.get(f"yanet-cli route get {route} ::/0")

    for route_row in routes:
        for interface_row in interfaces:
            if interface_row["module"] != route:
                continue
            if route_row["egress_interface"] == interface_row["interface"]:
                return

    raise Exception(f"check_default_v6('{route}')")


@Decorator.logger_function
@Decorator.skip_function()
def check_neighbor_v4(address_row, neighbors):
    for neighbor_row in neighbors:
        if (
            address_row["module"] == neighbor_row["route_name"]
            and address_row["interface"] == neighbor_row["interface_name"]
            and address_row["neighbor_v4"] == neighbor_row["ip_address"]
        ):
            return True
    return False


@Decorator.logger_function
@Decorator.skip_function()
def check_neighbor_v6(address_row, neighbors):
    for neighbor_row in neighbors:
        if (
            address_row["module"] == neighbor_row["route_name"]
            and address_row["interface"] == neighbor_row["interface_name"]
            and address_row["neighbor_v6"] == neighbor_row["ip_address"]
        ):
            return True
    return False


@Decorator.logger_function
@Decorator.skip_function()
def check_interfaces_neighbor_v4():
    interfaces = Executer.get("yanet-cli route interface")
    neighbors = Executer.get("yanet-cli neighbor show")
    for row in interfaces:
        if row["neighbor_v4"] != "n/s":
            if not check_neighbor_v4(row, neighbors):
                raise Exception(f"check_interfaces_neighbor_v4(): {row}")
    return


@Decorator.logger_function
@Decorator.skip_function()
def check_interfaces_neighbor_v6():
    interfaces = Executer.get("yanet-cli route interface")
    neighbors = Executer.get("yanet-cli neighbor show")
    for row in interfaces:
        if row["neighbor_v6"] != "n/s":
            if not check_neighbor_v6(row, neighbors):
                raise Exception(f"check_interfaces_neighbor_v6(): {row}")
    return


@Decorator.logger_function
@Decorator.skip_function(return_value=True)
def check_module(module):
    try:
        check_services()

        if module["type"] == "tun64":
            check_rib("ipv4 unicast")
            check_rib("ipv6 unicast")
            if module["next_module"].endswith(":tunnel"):
                check_default_v4(module["next_module"][:-7])
                check_default_v6(module["next_module"][:-7])
            else:
                check_default_v4(module["next_module"])
                check_default_v6(module["next_module"])
            check_interfaces_neighbor_v4()
            check_interfaces_neighbor_v6()
        elif module["type"] == "nat64stateful":
            check_rib("ipv4 unicast")
            check_rib("ipv6 unicast")
            if module["next_module"].endswith(":tunnel"):
                check_default_v4(module["next_module"][:-7])
                check_default_v6(module["next_module"][:-7])
            else:
                check_default_v4(module["next_module"])
                check_default_v6(module["next_module"])
            check_interfaces_neighbor_v4()
            check_interfaces_neighbor_v6()
        elif module["type"] == "decap":
            if module["next_module"].endswith(":tunnel"):
                check_rib("ipv4 unicast")
                check_rib("ipv6 unicast")
                check_default_v4(module["next_module"][:-7])
                check_default_v6(module["next_module"][:-7])
                check_interfaces_neighbor_v4()
                check_interfaces_neighbor_v6()
            else:
                check_rib("ipv4 unicast")
                check_default_v4(module["next_module"])
                check_interfaces_neighbor_v4()
        elif module["type"] == "nat64stateless":
            check_rib("ipv4 unicast")
            check_rib("ipv6 unicast")
            if module["next_module"].endswith(":tunnel"):
                check_default_v4(module["next_module"][:-7])
                check_default_v6(module["next_module"][:-7])
            else:
                check_default_v4(module["next_module"])
                check_default_v6(module["next_module"])
            check_interfaces_neighbor_v4()
            check_interfaces_neighbor_v6()
        elif module["type"] == "dregress":
            check_rib("ipv4 unicast")
            check_rib("ipv6 unicast")
            check_default_v4(module["next_module"])
            check_default_v6(module["next_module"])
            check_interfaces_neighbor_v4()
            check_interfaces_neighbor_v6()
        elif module["type"] == "balancer":
            check_rib("ipv6 unicast")
            check_default_v6(module["next_module"])
            check_interfaces_neighbor_v6()
        elif module["type"] == "firewall":
            check_rib("ipv6 unicast")
            check_default_v6(module["next_module"])
            check_interfaces_neighbor_v6()
    except Exception as error:
        if OPTIONS.dry_run:
            LOGGER.error("Fail: %s", error)

        return False
    return True


@Decorator.logger_function
@Decorator.skip_function(return_value=True)
def check_firewall_module():
    """Wrapper for firewall check module: allow to skip only firewall check."""
    firewall_module_definition: typing.Dict[str, str] = {
        "module": "firewall",
        "type": "firewall",
        "next_module": "route0",
    }

    return check_module(firewall_module_definition)


def signal_handler(signum, frame):
    global SIGNAL_RECV
    SIGNAL_RECV = True


def init_logger():
    global LOGGER

    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(logging.INFO)

    formatter = logging.Formatter("%(filename)s:%(lineno)s - %(levelname)s - %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    LOGGER.addHandler(handler)


def parse_args():
    global OPTIONS

    parser = argparse.ArgumentParser(description="YANET announcer", formatter_class=argparse.RawTextHelpFormatter)
    run_mode_group = parser.add_mutually_exclusive_group(required=True)
    run_mode_group.add_argument(
        "-r", "--run", action="store_true", default=False, dest="daemon", help="run as a daemon"
    )
    run_mode_group.add_argument(
        "-t", "--test", action="store_true", default=False, dest="dry_run", help="dry-run one time execution"
    )
    parser.add_argument(
        "-s",
        "--skip",
        type=str,
        nargs="*",
        default=[],
        dest="skip",
        help=textwrap.dedent(
            f"skipped checks names (keyword '{SKIP_CHECKS_ALL_KEYWORD}' disables all checks).\n"
            f"Option may be overridden with configuration '{SKIP_CHECKS_CONFIG_PARAM}' param."
        ),
    )
    OPTIONS = parser.parse_args()


def update_config():
    global ANNOUNCER_CONFIG
    global OPTIONS

    with open(CONFIGURATION_PATH) as f:
        ANNOUNCER_CONFIG = json.load(f)

    # Use skip checks for skip flag rewrite opts.
    # "pop" using for back compatibility with previous format,
    #   where ANNOUNCER_CONFIG contains only prefixes
    config_skip_checks: typing.Iterable[str] = ANNOUNCER_CONFIG.pop(SKIP_CHECKS_CONFIG_PARAM, [])
    if config_skip_checks and isinstance(config_skip_checks, abc.Iterable):
        OPTIONS.skip = config_skip_checks


def main():
    init_logger()
    parse_args()

    if OPTIONS.daemon:
        signal.signal(signal.SIGTERM, signal_handler)

    current_prefixes = []
    report_config_counter: int = 0
    report_getannounces_counter: int = 0
    is_firewall_machine: bool = False

    try:
        with open(MACHINE_TARGET_PATH, "r", encoding="UTF-8") as file:
            line = file.readline().rstrip()
            if "firewall" in line:
                is_firewall_machine = True
    except Exception as error:
        LOGGER.error("Failed to read target file: %s", error)

    while True:
        Executer.flush_cache()
        prefixes: typing.List[str] = []

        try:
            update_config()
            report_config_counter = 0
        except Exception as error:
            if report_config_counter == 0:
                LOGGER.error("Fail: %s", error)
            report_config_counter = 1
            time.sleep(1)
            continue

        try:
            for module in get_announces(["decap", "nat64stateless", "dregress", "balancer", "tun64", "nat64stateful"]):
                if OPTIONS.dry_run:
                    LOGGER.info(module)

                if check_module(module):
                    prefixes.extend(module["announces"])
            report_getannounces_counter = 0
        except Exception as error:
            if report_getannounces_counter == 0:
                LOGGER.error("Can not get announces with error: %s", error)
                report_getannounces_counter = 1
            if len(current_prefixes) > 0:
                LOGGER.warning(
                    "Problem with get_announce(dp/cp in down state?), remove current announces: %s", current_prefixes
                )
                bgp_remove(current_prefixes)

        if is_firewall_machine and check_firewall_module():
            prefixes.extend(["firewall::/128"])

        bgp_update(list(set(prefixes) - set(current_prefixes)))

        bgp_remove(list(set(current_prefixes) - set(prefixes)))

        if not OPTIONS.daemon:
            return

        current_prefixes = prefixes
        if SIGNAL_RECV:
            LOGGER.warning("Detect SIGNAL_RECV, remove announces and exit...")
            bgp_remove(current_prefixes)
            return

        time.sleep(1)


if __name__ == "__main__":
    main()
