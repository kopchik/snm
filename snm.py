#!/usr/bin/env python3

from useful.mystruct import Struct
from useful.mstring import s
from useful.log import Log
from useful.hook import Hook

from threading import Thread, Lock
from time import sleep
import shlex

from collections import OrderedDict, defaultdict
from socket import socket, AF_UNIX, SOCK_DGRAM
from subprocess import Popen, call, check_output
from os import unlink, getpid
import asyncio
import signal
import atexit
import time
import sys
import os

log = Log("main")

###########
# UTILITY #
###########


def run(cmd):
    log("run('%s')" % cmd)
    res = check_output(shlex.split(cmd)).decode(errors='ignore')
    log(res)
    return res


def run_(cmd):
    log("run_('%s')" % cmd)
    return call(shlex.split(cmd))


def runbg(cmd):
    log("runbg('%s')" % cmd)
    return Popen(shlex.split(cmd))


def iflist():
    return os.listdir('/sys/class/net')


def periodic(loop, period, f, *args, **kwargs):
    async def wrap():
        while True:
            f(*args, **kwargs)
            await asyncio.sleep(period)
    loop.run_until_complete(wrap())


def monitor_ifs(loop, hook, interfaces, poll=3):
    def on_ifchange(old, new):
        for ifname in old.difference(new):
            print("REMOVED IF:", ifname)
            if ifname in interfaces:
                iface = interfaces[ifname]
                hook.fire('del_if', iface)
                hook.fire(('del', iface))
        for ifname in new.difference(old):
            print("ADDED IF:", ifname)
            if ifname in interfaces:
                iface = interfaces[ifname]
                hook.fire('add_if', iface)
                hook.fire(('add', iface))

    old = set()
    async def monitor():
        nonlocal old
        while True:
            new = set(iflist())
            if new != old:
                on_ifchange(old, new)
                old = new
            else:
                log.debug("no newinterfaces")
            await asyncio.sleep(poll)
    loop.run_until_complete(monitor())


class Nethook(Hook):

    def __init__(self, loop):
        super().__init__()
        self.sigchld_handlers = defaultdict(set)
        signal.signal(signal.SIGCHLD, self.on_sigchld)

    def waitpid(self, pid, cb):
        self.sigchld_handlers[pid].add(cb)

    def on_sigchld(self):
        pid, st = os.waitpid(-1, os.WNOHANG)
        if not pid:
            return log.error("spurious SIGCHLD")
        if pid not in self.sigchld_handlers:
            return log.error(
                "pid %s is not monitored (status: %s)" %
                (pid, st))
        for cb in self.sigchld_handlers[pid]:
            try:
                cb(st)
            except Exception as err:
                log.critical(
                    "SIGCHLD: error in cb %s (pid: %s, st: %s): %s" %
                    (cb, pid, st, err))

    async def run(self):
        while True:
            await asyncio.sleep(1)


class Common:

    def __init__(self, hook=None):
        self.hook = hook


class Connection(Common):

    def __init__(self, interface, descr=None, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self.descr = descr

    def reconnect(self):
        self.disconnect()
        self.connect()

    def connect(self):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError


interfaces = {}
class Interface:

    def __init__(self, name):
        self.name = name
        interfaces[name] = self

    def up(self):
        raise NotImplementedError

    def down(self):
        raise NotImplementedError


class Ether(Interface):

    def __init__(self, promisc=False, **kwargs):
        super().__init__(**kwargs)
        self.promisc = False

    def up(self, promisc=False):
        run(s("ifconfig ${self.name} up"))
        if promisc or self.promisc:
            run(s("ifconfig ${self.name} promisc on"))

    def down(self):
        run_(s("ifconfig ${self.name} down"))
        run_(s("ifconfig ${self.name} 0.0.0.0"))
        if self.promisc:
            run(s("ifconfig ${self.name} promisc off"))


class DHCP(Connection):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pipe = None

    def connect(self):
        self.interface.up()
        self.pipe = runbg(s("dhcpcd -t 5 -B ${self.interface.name}"))
        self.dispatcher.waitpid(self.pipe.pid, lambda: log.debug("dhcp died"))
        self.dispatcher.waitpid(self.pipe.pid, self.disconnect)

    def disconnect(self):
        if self.pipe:
            run_(s("dhcpcd ${self.interface.name} -k"))
            try:
                self.pipe.wait(3)
            except TimeoutExpired:
                self.pipe.kill()
        # self.interface.down()


class WiFiScanner(Thread):

    def __init__(self, ifname, interval=5):
        self.ifname = ifname
        self.result = []
        run(s("wpa_cli -i ${self.ifname} scan_interval ${interval}"))
        run(s("wpa_cli -i ${self.ifname} scan"))
        super().__init__(daemon=True)

    def run(self):
        while True:
            try:
                result = []
                raw = run(s(
                    "wpa_cli -i ${self.ifname} scan_results")).splitlines()
                rawfields = raw.pop(0)
                fields = rawfields.split(" / ")
                for line in raw:
                    data = line.split('\t')
                    result.append(Struct(**dict(zip(fields, data))))
                self.result = result  # atomic update
                [print(bs) for bs in result]
            except Exception as e:
                log.error(e)
                sleep(1)
            sleep(5)


def parse_status(msg):
    return OrderedDict(s.split('=') for s in msg.strip().splitlines())


PID = getpid()


class Network:
    pass


class OpenNetwork(Network):

    def __init__(self, ssid, bssid=None):
        self.ssid = ssid
        self.bssid = bssid

    def wpacfg(self):
        cmds = []
        cmds.append("ssid \"%s\"" % self.ssid)
        cmds.append("key_mgmt NONE")
        if self.bssid:
            cmds.append("bssid %s" % self.ssid)
        return cmds

    def on_connect(self):
        TODO

    def on_disconnect(self):
        TODO


events = defaultdict(list)


class WPAMonitor(Thread):

    def __init__(self, ifname):
        self.log = Log("monitor")
        mon_path = "/tmp/wpa_mon_%s" % PID
        atexit.register(lambda: unlink(mon_path))
        server_path = "/var/run/wpa_supplicant/%s" % ifname
        self.log.debug("connecting to %s" % server_path)
        self.socket = socket(AF_UNIX, SOCK_DGRAM)
        self.socket.bind(mon_path)
        self.socket.connect(server_path)
        self.events = defaultdict(list)
        super().__init__(daemon=True)

    def run(self):
        self.socket.send(b"AUTOSCAN periodic:10")
        self.socket.send(b"AP_SCAN 1")
        self.socket.send(b"ATTACH")

        while True:
            try:
                data = self.socket.recv(65535).strip().decode('ascii',
                                                              'ignore')
                self.log.debug("got %s" % data)
                if data == 'OK':
                    continue
                if data == 'FAIL':
                    raise Exception("Failure detected")
                mask, evtype = data.split('>', 1)
                if evtype == 'CTRL-EVENT-SCAN-RESULTS':
                    print("scan results")
                    for cb in events['scan_results']:
                        cb()
                else:
                    self.log.info("unknown event %s" % data)
            except Exception as e:
                self.log.critical(e)
                sys.exit(e)


class WPAClient:

    def __init__(self, ifname):
        self.log = Log("WPA %s" % ifname)
        client_path = "/tmp/wpa_client_%s" % PID
        atexit.register(lambda: unlink(client_path))
        server_path = "/var/run/wpa_supplicant/%s" % ifname
        self.socket = socket(AF_UNIX, SOCK_DGRAM)
        self.socket.bind(client_path)
        self.log.debug("using %s wpa socket..." % server_path)
        self.socket.connect(server_path)
        self.lock = Lock()

    def send(self, msg):
        self.log.debug("sending: %s" % msg)
        if isinstance(msg, str):
            msg = msg.encode('ascii', errors='ignore')
        self.socket.send(msg)

    def recv(self, bufsize=65535):
        r = self.socket.recv(bufsize)
        return r.strip().decode('ascii', errors='ignore')

    def run(self, cmd, check=True):
        with self.lock:
            self.send(cmd)
            r = self.recv()
            self.log.debug("received: %s" % r)
            if check:
                assert r not in ['FAIL', 'UNKNOWN COMMAND']
        return r

    def status(self):
        raw_status = self.run("STATUS", check=False)
        return parse_status(raw_status)

    def scan_results(self):
        result = []
        raw_results = self.run("SCAN_RESULTS")
        for line in raw_results.splitlines()[1:]:
            bssid, freq, signal, flags, ssid = line.split()
            r = Struct(ssid=ssid,
                       signal=signal,
                       bssid=bssid,
                       freq=freq,
                       flags=flags)
            result.append(r)
        return result

    def connect(self, network):
        nid = self.run("ADD_NETWORK")
        for cmd in network.wpacfg():
            self.run(s("SET_NETWORK ${nid} ${cmd}"))
        self.run(s("SELECT_NETWORK ${nid}"))
        self.run(s("ENABLE_NETWORK ${nid}"))


def main():
    loop = asyncio.get_event_loop()
    hook = Nethook(loop)
    iface = Ether(name='eth0')
    conn = DHCP(interface=iface, hook=hook)
    monitor_ifs(loop, hook, interfaces)
    time.sleep(100000)

if __name__ == '__main__':
    main()
#  ifname = 'wlan0'
#  wpa = WPAClient(ifname)
#  monitor = WPAMonitor(ifname)
#  monitor.start()
#  unitn = OpenNetwork('unitn')
#
#  from gi.repository import Gtk
#  builder = Gtk.Builder()
#  builder.add_from_file("interface.glade")
#  window = builder.get_object("MainWindow")
#  window.connect("delete-event", Gtk.main_quit)
#  window.show_all()
#
#  netstore = builder.get_object("NetStore")
#  def on_scan_results():
#    results = wpa.scan_results()
#    netstore.clear()
#    for r in results:
#      netstore.append([int(r.signal), r.ssid, r.bssid])
#  events['scan_results'].append(on_scan_results)
#
#  import signal
#  signal.signal(signal.SIGINT, signal.SIG_DFL)
#  Gtk.main()
