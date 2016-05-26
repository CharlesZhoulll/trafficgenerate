# Remember run this piece of program in command line
# Do not try to click Run directly! Would not work !

import sys, threading, os, subprocess
import sys, signal

nServers = 1
basePort = 10000
time = 10
procs = []

def finish(*args):
    print "Close all servers."
    for proc in procs:
        try:
            proc.terminate()
        except:
            pass
    sys.exit(0)
    
def startServer(serverID, port):
    print "Server %s start, listen on port: %d \n" % (serverID, port)
##    if port == 10000:
##        time = 80
##    elif port == 20000:
##        time = 60
##    elif port == 30000:
##        time = 40
##    else:
##        time = 20
    cmd = './tcpserver' + ' -t ' + str(time) + ' -p ' + str(port)
    #cmd = "ping google.com"
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell = True)
    procs.append(proc)
    #line = proc.stdout.readline()
    #print line
    line = proc.stderr.readline()
    print line 
    line = proc.stdout.read()
    print line

    
def run():
    os.system("pkill tcpserver")
    for i in xrange(nServers):
        port = (i + 1) * basePort
        thread = threading.Thread(target = startServer, args = (i + 1, port))
        thread.start()
    signal.signal(signal.SIGINT, finish)
    signal.pause()
    
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        nServers = int(sys.argv[1])
        time = int(sys.argv[2])
    run()
