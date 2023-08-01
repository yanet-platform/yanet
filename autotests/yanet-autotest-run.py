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


p_dataplane = None
p_controlplane = None


def string_generator(size=8, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))


def kill_processes():
	for process in [p_dataplane, p_controlplane]:
		if process is None:
			continue

		os.killpg(os.getpgid(process.pid), signal.SIGTERM)
		process.wait()


def wait_application(application):
	for tries in range(1, 30):
		if os.system("yanet-cli version | grep --silent %s" % application) == 0:
			return
		time.sleep(1)
	kill_processes()
	sys.exit(1)


atexit.register(kill_processes)

units = []
if len(sys.argv) < 3:
	for name in os.listdir("%s" % (sys.argv[1])):
		if name == "disabled":
			continue

		full_path = os.path.join("%s" % (sys.argv[1]), name)
		if os.path.isdir(full_path):
			units.append(full_path)
	units.sort()
else:
	units = sys.argv[2:]


os.makedirs("/run/yanet", exist_ok=True)

p_dataplane = subprocess.Popen("yanet-dataplane -d -c %s/dataplane.conf" % (sys.argv[1]),
                               shell=True, preexec_fn = os.setsid)

wait_application("dataplane")

p_controlplane = subprocess.Popen("yanet-controlplane -d",
                                  shell=True, preexec_fn = os.setsid)

wait_application("controlplane")

p_autotest = subprocess.Popen("yanet-autotest -n %s" % (" ".join(units)),
                              shell=True)

p_autotest.wait()
if p_autotest.returncode != 0:
	kill_processes()
	with open("/tmp/yanet-dp.report", "r") as fin:
		print(fin.read())
	sys.exit(2)

if (p_dataplane.poll() != None) or (p_controlplane.poll() != None):
	kill_processes()
	with open("/tmp/yanet-dp.report", "r") as fin:
		print(fin.read())
	sys.exit(3)

kill_processes()
