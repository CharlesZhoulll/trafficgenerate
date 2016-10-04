#!/usr/bin/python
import paramiko, multiprocessing
import sys, signal
import os
from scp import SCPClient

host = "129.10.99.173" # Remote server ip address
uname = "fan_tcp" # Username
password = "Ell-301" # Need for sudo execute command
rsa = "/home/charles/.ssh/id_rsa" # Need for auto login
remoteModuleDir = "/home/fan_tcp/Documents/fan/tcpprofiling/tcp_probe/" # Remote working dir
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
    if not fetch(remoteModuleDir + traceFile):
        print "Error ! Fail to retrieve profile, please check to see if your tcp probe module work properly !"
        sys.exit(0)
    parse(traceFile)
    sys.exit(0)

def cleanTcpProbe():
    print "Stop probing ..."
    client = connect()
    cmds = []
    cmds.append('pkill cat')
    cmds.append('rmmod ' + remoteModuleDir + 'tcp_tuning.ko')
    for cmd in cmds:
        execute(client, cmd, True)

def fetch(fileDirectory):
    print('Fetching ' + fileDirectory)
    client = connect()
    try:
        scp = SCPClient(client.get_transport())
        scp.get(fileDirectory)
        scp.close()
        client.close()
        return True
    except:
        client.close()
        return False

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

def preHandle(rates):
    configString = ""
    ratelist = rates.split("\n");
    for rate in ratelist:
        info = rate.split(" ")
        if len(info) == 2:
            try:
                if  (0<int(info[0])<= 65535) and (int(info[1]) >= 0):
                    configString += info[0]+":"+info[1] + "."
                    continue
            except ValueError:
                pass
        print "Error in config file, at: " + rate
    return configString

def startTcpTuning():
    print "Running remote probing at host %s:%s" % (host, port)
    print "Press CTRL+C to terminate..."
    configString = preHandle(config_content)
    if not configString:
        print "Nothing to be done."
        return
    client = connect()
    cmds = []
    cmds.append('rmmod ' + remoteModuleDir + 'tcp_probe_fixed.ko')
    cmds.append('insmod ' + remoteModuleDir + 'tcp_probe_fixed.ko '
                + 'procname=' + '\"' + traceFile + '\"'
                + ' config=' + '\"' + configString + '\"')
    cmds.append('chmod 444 /proc/net/' + traceFile)
    cmds.append('cat /proc/net/' + traceFile + ' > ' + remoteModuleDir + traceFile)
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
