#!/usr/bin/env python3
from useful.mstring import s
from useful.log import Log
from subprocess import call, check_call, Popen
import shlex

def run(cmd):
  return check_call(shlex.split(cmd))

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
  def connect(self):
    # import pdb
    # pdb.set_trace()
    run(s("ifconfig ${self.ifname} up"))

  def disconnect(self):
    run_(s("ifconfig ${self.ifname} down"))
    run_(s("ifconfig ${self.ifname} 0.0.0.0"))


class DHCP(Conn):
  def __init__(self, *args, **kwargs):
    self.pipe = None
    super().__init__(*args, **kwargs)
  def connect(self):
    self.pipe = runbg(s("dhcpcd -t 3 ${self.ifname}"))

  def disconnect(self):
    if self.pipe:
      self.pipe.kill()

if __name__ == '__main__':
  # ether = Ether("testtap", "Test")
  # ether.reconnect()
  dhcp = DHCP("testtap")
  dhcp.reconnect()