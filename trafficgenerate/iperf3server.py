import sys, threading, os, subprocess
import sys, signal

nServers = 1
basePort = 10000
time = 10
procs = []

def finish(*args):
    os.system("pkill iperf3")
    sys.exit(0)

def startServer(serverID, port):
    cmd = 'iperf3' + ' -s ' + ' -p ' + str(port)
    os.system(cmd)

def run():
    os.system("pkill iperf3")
    for i in xrange(nServers):
        port = basePort + i
        thread = threading.Thread(target = startServer, args = (i + 1, port))
        thread.start()
    signal.signal(signal.SIGINT, finish)
    signal.pause()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        nServers = int(sys.argv[1])
        basePort = int(sys.argv[2])
    run()
