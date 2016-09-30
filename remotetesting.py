#!/usr/bin/python
import paramiko, multiprocessing
import sys, signal
import os
from scp import SCPClient

host = "129.10.99.173" # Remote server ip address
uname = "fan_tcp" # Username
password = "Ell-301" # Need for sudo execute command
rsa = "/home/charles/.ssh/id_rsa" # Need for auto login
remoteAddr = "/home/fan_tcp/Documents/fan/tcpprobe/" # Remote working dir
traceFile = "tcptrace" # Tracefile name
port = 12345 # Port the tcpprobe should listen to
jobs = []

def parse(traceFile):
    if not os.path.exists(traceFile):
        print "Fetch file fail...return"
        return
    with open(traceFile) as f:
        content = f.readlines()
    fwDist= {}
    for line in content:
        sURL = line.split()[1]
        sPort = sURL.split(":")[1]
        if fwDist.has_key(sPort):
            fwDist[sPort].write(line)
        else:
            traceFileName = traceFile + '.' + sPort
            fw = open(traceFileName,'w')
            fwDist[sPort] = fw
            fw.write(line)
    for sPort in fwDist:
        fwDist[sPort].close()

def finish(*args):
    for job in jobs:
        if job.is_alive():
            job.terminate()
            job.join()
    cleanTcpProbe()
    fetch(remoteAddr + traceFile)
    parse(traceFile)
    os.remove(traceFile)
    sys.exit(0)

def cleanTcpProbe():
    print "Stop tcptuning ..."
    client = connect()
    cmds = []
    cmds.append('pkill cat')
    cmds.append('rmmod ' + remoteAddr + 'tcp_tuning.ko')
    for cmd in cmds:
        execute(client, cmd, True)

def fetch(fileDirectory):
    print('Fetching ' + fileDirectory)
    client = connect()
    scp = SCPClient(client.get_transport())
    scp.get(fileDirectory)
    scp.close()
    client.close()

def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    rsaKey = paramiko.RSAKey.from_private_key_file(rsa)
    client.connect(host, username=uname, pkey = rsaKey)
    return client

def execute(client, cmd, sudo):
    stdin, stdout, stderr = client.exec_command("sudo -S %s" % cmd)
    if sudo is True:
        stdin.write(password + '\n')
        stdin.flush()
    return stderr.read()

def startTcpTuning():
    print "Running remote testing ..."
    client = connect()
    cmds = []
    cmds.append('rmmod ' + remoteAddr + 'tcp_probe_fixed.ko')
    cmds.append('insmod ' + remoteAddr + 'tcp_probe_fixed.ko '
                + 'procname=' + '\"' + traceFile)
    cmds.append('chmod 444 /proc/net/' + traceFile)
    cmds.append('cat /proc/net/' + traceFile + ' > ' + remoteAddr + traceFile)
    for cmd in cmds:
        execute(client, cmd, True)
    client.close()

def run():
    # First clean old tcptrace file
    try:
        os.remove(traceFile)
    except OSError:
        pass
    client = connect()
    jobs.append(multiprocessing.Process(target=startTcpTuning))
    for job in jobs:
        job.start()
    signal.signal(signal.SIGINT, finish)
    signal.pause()

if __name__ == '__main__':
    # Two parameter allowed,
    if len(sys.argv) >= 2:
        traceFile = sys.argv[1]
        if len(sys.argv) == 3:
            port = sys.argv[2]
    run()
