#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import subprocess
import sys
import string
import random
import signal
import atexit
import optparse

class Autotest:
    def __init__(self, debug, keep, prefix):
        self.debug = debug
        self.keep = keep
        self.prefix = prefix

        self.p_dataplane = None
        self.p_controlplane = None
        self.p_autotest = None

    def export_path(self):
        if self.prefix:
            applications = ["dataplane", "controlplane", "cli", "autotest"]
            for application in applications:
                os.environ["PATH"] += f":{self.prefix}/{application}"

    def wait_application(self, application):
        for tries in range(1, 30):
            if os.system(f"yanet-cli version | grep --silent {application}") == 0:
                return
            time.sleep(1)

        self.kill_processes()
        sys.exit(2)

    def kill_processes(self):
        for process in [self.p_autotest, self.p_controlplane, self.p_dataplane]:
            if process is None:
                continue

            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait()
            except:
                pass

    def run_dataplane(self, dataplane_conf_path):
        command = "yanet-dataplane"
        if self.debug:
            command += " -d"
        command += f" -c {dataplane_conf_path}"

        self.p_dataplane = subprocess.Popen(command, shell=True, preexec_fn = os.setsid)
        self.wait_application("dataplane")

    def run_controlplane(self):
        command = "yanet-controlplane"
        if self.debug:
            command += " -d"

        self.p_controlplane = subprocess.Popen(command, shell=True, preexec_fn = os.setsid)
        self.wait_application("controlplane")

    def run_autotest(self, units):
        command = "yanet-autotest " + " ".join(units)

        self.p_autotest = subprocess.Popen(command, shell=True)

    def start(self, dataplane_conf_path, units):
        self.export_path()
        os.makedirs("/run/yanet", exist_ok=True)

        self.run_dataplane(dataplane_conf_path)
        self.run_controlplane()
        self.run_autotest(units)

        if self.keep:
            self.p_autotest.wait()
            self.p_controlplane.wait()
            self.p_dataplane.wait()
            return

        self.p_autotest.wait()
        if self.p_autotest.returncode != 0:
            self.kill_processes()
            if self.debug:
                with open("/tmp/yanet-dp.report", "r") as fin:
                    print(fin.read())
            sys.exit(3)

        if (self.p_dataplane.poll() != None) or (self.p_controlplane.poll() != None):
            self.kill_processes()
            if self.debug:
                with open("/tmp/yanet-dp.report", "r") as fin:
                    print(fin.read())
            sys.exit(4)

        self.kill_processes()

def main():
    usage = "usage: %prog [options] units_group [units ...]"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-d", "--debug", action="store_true", default=False, dest="debug", help="enable debug mode")
    parser.add_option("-k", "--keep", action="store_true", default=False, dest="keep", help="keep processes running after autotest")
    parser.add_option("--prefix", default="", dest="prefix", help="add prefix for bin path")
    opt, args = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        return 1

    autotest = Autotest(opt.debug, opt.keep, opt.prefix)

    atexit.register(autotest.kill_processes)

    dataplane_conf_path = args[0] + "/dataplane.conf"
    units = []
    if len(args) == 1:
        for name in os.listdir("%s" % (args[0])):
            if name == "disabled":
                continue

            full_path = os.path.join("%s" % (args[0]), name)
            if os.path.isdir(full_path):
                units.append(full_path)

        units.sort()
    else:
        units = args[1:]

    autotest.start(dataplane_conf_path, units)
    return 0

if __name__ =="__main__":
    sys.exit(main())
