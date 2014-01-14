#!/usr/bin/env python3
from useful.mystruct import Struct
from useful.mstring import s
from useful.log import Log

from subprocess import call, check_output, Popen, TimeoutExpired
from functools import partial
from threading import Thread
from time import sleep
import shlex

Log.set_global_level('debug')
log = Log("main")

def run(cmd):
  res = check_output(shlex.split(cmd)).decode(errors='ignore')
  log(cmd)
  log(res)
  return res

def run_(cmd):
  return call(shlex.split(cmd))

def runbg(cmd):
  return Popen(shlex.split(cmd))


class Conn:
  def __init__(self, ifname, descr=None):
    self.ifname = ifname
    self.descr = descr

  def reconnect(self):
    self.disconnect()
    self.connect()

  def connect(self):
    raise NotImplementedError

  def disconnect(self):
    raise NotImplementedError


class Ether(Conn):
  def connect(self, promisc=False):
    self.promisc = promisc
    run(s("ifconfig ${self.ifname} up"))
    if self.promisc:
      run(s("ifconfig ${self.ifname} promisc on"))

  def disconnect(self):
    run_(s("ifconfig ${self.ifname} down"))
    run_(s("ifconfig ${self.ifname} 0.0.0.0"))
    if self.promisc:
      run(s("ifconfig ${self.ifname} promisc off"))


class DHCP(Conn):
  def __init__(self, *args, **kwargs):
    self.pipe = None
    super().__init__(*args, **kwargs)

  def connect(self):
    self.pipe = runbg(s("dhcpcd -t 3 ${self.ifname}"))

  def disconnect(self):
    if self.pipe:
      run_(s("dhcpcd ${self.ifname} -k"))
      try:
        self.pipe.wait(3)
      except TimeoutExpired:
        self.pipe.kill()


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
        raw = run(s("wpa_cli -i ${self.ifname} scan_results")).splitlines()
        rawfields = raw.pop(0)
        fields = rawfields.split(" / ")
        for line in raw:
          data = line.split('\t')
          result.append( Struct(**dict(zip(fields, data))) )
        self.result = result  # atomic update
        [print(bs) for bs in result]
      except Exception as e:
        log.error(e)
        sleep(1)
      sleep(5)


class WPA(Ether):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.log = Log("WPA(%s)"%self.ifname)
    self.netid = None

  def connect_open(self, ssid):
    self.netid = int(self.execute("add_network"))
    self.log.debug("created network %s" % self.netid)
    self.ssid(ssid)
    self.key_mgmt(None)

  def __getattr__(self, param):
    return partial(self.execute, 'set_network', self.netid, param)

  def execute(self, *cmd):
    mapping = {type(None): lambda s: "NONE",
               int: str,
               str: lambda s: '"'+s+'"'}
    cmd = " ".join([mapping[type(s)](s) for s in cmd])
    cmd = s("wpa_cli -i ${self.ifname} ${cmd}")
    self.log.debug("executing %s"%cmd)
    res = run(cmd).strip()
    self.log.debug("result: %s"%res)
    return res

  def connect(self):
    super().connect()

  def disconnect(self):
    super().disconnect()



if __name__ == '__main__':
  # ether = Ether("testtap", "Test")
  # ether.reconnect()
  # dhcp = DHCP("testtap")
  # dhcp.reconnect()

  # scanner = WiFiScanner("wlan0")
  # scanner.start()
  # scanner.join()
  # wifi = WiFi('unitn', ifname='wlan0')
  wpa = WPA('wlan0')
  wpa.connect_open('unitn')