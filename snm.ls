{head, tail} = require 'prelude-ls'
p = console.log
spawn = require 'child_process' .spawn

run_cmd = !(cmd, done) ->
  cmd = cmd.split(" ") unless (cmd instanceof Array)
  done = p unless (typeof done == \function)
  progname = head cmd
  args = tail cmd
  p progname, args
  child = spawn progname, args
  result = stdout: ''
  child.stdout
    ..on \data !(buffer) ->
      result.stdout += buffer
    ..on \end !->
      done result


class Conn
  reconnect: ~>
    @disconnect!
    p!
    @connect!


class Ether extends Conn
  (@ifname, @name)   ~>
    p "creating connection #{@name} (#{@ifname})"

  status:     ~>
    p "status for #{@name} #{@ifname}"

  connect:    ~>
    p "connecting to #{@name} (#{@ifname})"
    run_cmd "ifconfig #{@ifname} up"

  disconnect: ~>
    p "disconnecting #{@name} (#{@ifname})"
    run_cmd "ifconfig #{@ifname} down"
    run_cmd "ifconfig #{@ifname} 0.0.0.0"


ether = new Ether \testtap "Wired DHCP"
ether.reconnect!
