#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import subprocess
import sys
import string
import random
import signal


def string_generator(size=8, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def kill_processes(processes):
	for process in processes:
		os.killpg(os.getpgid(process.pid), signal.SIGTERM)
		process.wait()

os.makedirs("/run/yanet", exist_ok=True)
p_dataplane = subprocess.Popen("yanet-dataplane -d -c units/%s/dataplane.conf" % (sys.argv[1]),
                               shell=True, preexec_fn = os.setsid)

time.sleep(20)

p_controlplane = None

for tries in range(1, 5):
	p_controlplane = subprocess.Popen("yanet-controlplane -d",
                                  shell=True, preexec_fn = os.setsid)
	time.sleep(tries * 10)
	if p_controlplane.poll() == None:
		break

if (p_dataplane.poll() != None) or (p_controlplane.poll() != None):
	kill_processes([p_controlplane, p_dataplane])
	sys.exit(1)

time.sleep(10)

units = []
if len(sys.argv) == 4 and sys.argv[2] == "--part":
	for name in os.listdir("units/%s" % (sys.argv[1])):
		if name == "disabled":
			continue

		full_path = os.path.join("units/%s" % (sys.argv[1]), name)
		if os.path.isdir(full_path):
			units.append(full_path)
	units.sort()

	current, maximum = sys.argv[3].split('/', 1)
	step = int(len(units) / int(maximum))
	if current != maximum:
		units = units[(int(current) - 1) * step : int(current) * step]
	else:
		units = units[(int(current) - 1) * step : ]
elif len(sys.argv) < 3:
	for name in os.listdir("units/%s" % (sys.argv[1])):
		if name == "disabled":
			continue

		full_path = os.path.join("units/%s" % (sys.argv[1]), name)
		if os.path.isdir(full_path):
			units.append(full_path)
	units.sort()
else:
	units = sys.argv[2:]

p_autotest = subprocess.Popen("yanet-autotest -n %s" % (" ".join(units)),
                              shell=True)

p_autotest.wait()
if p_autotest.returncode != 0:
	kill_processes([p_controlplane, p_dataplane])
	with open("/tmp/yanet-dp.report", "r") as fin:
		print(fin.read())
	sys.exit(2)

if (p_dataplane.poll() != None) or (p_controlplane.poll() != None):
	kill_processes([p_controlplane, p_dataplane])
	with open("/tmp/yanet-dp.report", "r") as fin:
		print(fin.read())
	sys.exit(3)

kill_processes([p_controlplane, p_dataplane])
