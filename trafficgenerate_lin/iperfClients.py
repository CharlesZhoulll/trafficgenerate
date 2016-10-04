import sys, threading, os, subprocess
import sys, signal

nClients = 1
basePort = 10000
serverIp = '129.10.99.173'
time = 10
procs = []

def finish(*args):
    os.system("pkill iperf3")
    sys.exit(0)

def startServer(serverID, port):
    cmd = 'iperf3' + ' -R  -c ' + serverIp + ' -p ' + str(port) + ' -t ' + str(time)
    print cmd
    os.system(cmd)

def run():
    os.system("pkill iperf3")
    for i in xrange(nClients):
        port = basePort + i
        thread = threading.Thread(target = startServer, args = (i + 1, port))
        thread.start()
    signal.signal(signal.SIGINT, finish)
    signal.pause()

if __name__ == '__main__':
    print "Parameters: nClients, basePort, serverIp, time"
    if len(sys.argv) >= 4:
        nClients = int(sys.argv[1])
        basePort = int(sys.argv[2])
        serverIp = sys.argv[3]
        time = int(sys.argv[4])
    run()
