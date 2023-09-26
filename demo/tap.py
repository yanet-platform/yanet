#!/usr/bin/env python3

import sys
import optparse
import socket
import struct
import threading
import pytun

class Tunnel:
    def __init__(self, interface, mtu):
        self.interface = interface
        self.mtu = mtu

        self.tap = pytun.TunTapDevice(flags = pytun.IFF_TAP | pytun.IFF_NO_PI,
                                      name = interface)
        self.tap.mtu = mtu

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def tap_thread(self):
        while True:
            tap_buffer = self.tap.read(self.tap.mtu)

            tap_data = struct.pack(">I",
                                   len(tap_buffer))

            self.sock.send(tap_data)
            self.sock.send(tap_buffer)

    def sock_thread(self):
        while True:
            sock_buffer = self.sock.recv(self.mtu + 4)
            sock_buffer = sock_buffer[4:]

            self.tap.write(sock_buffer)

    def start(self):
        try:
            self.tap.up()
            self.sock.connect(f"/run/yanet/{self.interface}")

            thread1 = threading.Thread(target=self.tap_thread, name="tap_thread")
            thread2 = threading.Thread(target=self.sock_thread, name="sock_thread")

            thread1.start()
            thread2.start()

            thread1.join()
            thread2.join()
        except Exception as exception:
            print(exception)

        self.tap.down()
        self.tap.close()
        self.sock.close()

def main():
    parser = optparse.OptionParser()
    parser.add_option("--interface", dest="interface", help="set tunnel interface")
    parser.add_option("--mtu", type="int", default=1500, dest="mtu", help="set tunnel MTU")
    opt, args = parser.parse_args()

    if not opt.interface:
        parser.error("tunnel interface not given")

    tunnel = Tunnel(opt.interface, opt.mtu)
    tunnel.start()
    return 0

if __name__ =="__main__":
    sys.exit(main())
