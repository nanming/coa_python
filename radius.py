#!/usr/bin/env python

import random, socket, sys
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import time, platform, os
import threading
import SocketServer

def Usage():
    print(
"""
Usage: radius.py auth nasip userip username passwd radius_addr radius_secret
       radius.py acct <start|update|stop> nasip userip usermac 
       inputotect outputotect acctsessiontime acctsessionid username  radius_addr radius_secret
    
OPTIONS
        start
            Acctouting start request
        update
            Update the accounting message
        stop
            Stop accounting
PARAMETERS
        nasip
            Nas ip address, now the nas ip address is the portal server
        userip
            Sta's ip address
        usermac
            Sta's MAC
        inputotect
            The flow sta received (KB)
        outputotect 
            The flow sta has been sent (KB)
        acctsessiontime
            The time the user has received service for
        acctsessionid
            Accounting session id
        username
            The user's name
        radius_addr 
            The radius server' address
        radius_secret
            The radius server' share secret
EXAMPLES
        radius.py auth 192.168.1.100 192.168.2.103 user0 123456 115.29.203.202 testing123

        radius.py acct update 192.168.1.100 192.168.2.103 38:BC:1A:A0:58:6A 1024 1023 360 1234567890abc user0 115.29.203.202 testing123
""")

def check_ip(ipaddr):
    addr=ipaddr.strip().split('.') 
    if len(addr) != 4: 
            #return >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
            return -1
    for i in range(4):
            try:
                    addr[i]=int(addr[i]) 
            except:
                      #return >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
		    return -1
            if addr[i]<=255 and addr[i]>=0:   
                    pass
            else:
		    #return >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
		    return -1
            i+=1

def SendPacket(srv, req):
    try:
        return srv.SendPacket(req)
    except pyrad.client.Timeout:
        #return "RADIUS server does not reply"
        return -1
    except socket.error, error:
        #return "Network error: " + error[1]
        #sys.exit(1)
        return -1

def DealData(data):

    acct_list = ['start', 'update', 'stop']

    if len(data) == 7 and data[0] == 'auth':
        # data[1] nasip
        # data[2] userip
        # data[3] username
        # data[4] password
        # data[5] radius addr
        # data[6] radius secret
        check_ip(data[1])
        check_ip(data[2])
        #if dict_client.has_key(data[5]):
            #srv = dict_client[data[5]]
        #else:
        srv=Client(server=data[5],
	   secret=data[6], dict=dictionary)
        #    dict_client[data[5]] = srv
               #dict=Dictionary("/usr/local/share/freeradius/dictionary"))

        req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                 User_Name=data[3])

        req["User-Password"]      = req.PwCrypt(data[4])
        req["NAS-IP-Address"]     = data[1]
        #req["NAS-Port"]           = 0
        #req["Service-Type"]       = "Login-User"
        #req["NAS-Identifier"]     = "trillian"
        #req["Called-Station-Id"]  = "00-04-5F-00-0F-D1"
        #req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        req["Framed-IP-Address"]  = data[2]

        reply = SendPacket(srv, req)

        if not isinstance(reply, pyrad.packet.Packet):
            return -1
        if reply.code==pyrad.packet.AccessAccept:
            if reply:
                return reply['Acct-Interim-Interval'][0]
            else:
                return 0
        else:
            return -2
    elif len(data) == 12 and data[0] == 'acct' and data[1] in acct_list:
        # data[1] auth type
        # data[2] nasip
        # data[3] userip
        # data[4] usermac
        # data[5] inputotect
        # data[6] outputotect
        # data[7] acctsessiontime
        # data[8] acctsessionid
        # data[9] username
        # data[10] radius addr
        # data[11] radius secret
        #if dict_client.has_key(data[10]):
            #srv = dict_client[data[10]]
        #else:
        srv=Client(server=data[10],
	       secret=data[11], dict=dictionary)
            #dict_client[data[10]] = srv
                   #dict=Dictionary("/usr/local/share/freeradius/dictionary"))

        req=srv.CreateAcctPacket(User_Name=data[9])

        if data[1] == 'start':
            req["NAS-IP-Address"]=data[2]
            #req["NAS-Port"]=0
            #req["NAS-Identifier"]="trillian"
            #req["Called-Station-Id"]="00-04-5F-00-0F-D1"
            req["Calling-Station-Id"]=data[4]
            req["Framed-IP-Address"]=data[3]
	    acctSessionId = ''.join(data[4].split(':'))+str(time.time())
            req["Acct-Session-Id"]=acctSessionId
            req["Acct-Status-Type"]="Start"
	    SendPacket(srv, req)
	    return  acctSessionId
        elif data[1] == 'update':
            req["NAS-IP-Address"]=data[2]
            req["Acct-Input-Octets"] = int(data[5])
            req["Acct-Output-Octets"] = int(data[6])
            req["Acct-Session-Time"] = int(data[7])
            req["Calling-Station-Id"]=data[4]
            req["Framed-IP-Address"]=data[3]
            req["Acct-Session-Id"]=data[8]
            req["Acct-Status-Type"]="Interim-Update"
	    SendPacket(srv, req)
            return 0
        else:
            req["NAS-IP-Address"]=data[2]
            req["Acct-Input-Octets"] = int(data[5])
            req["Acct-Output-Octets"] = int(data[6])
            req["Acct-Session-Time"] = int(data[7])
            req["Calling-Station-Id"]=data[4]
            req["Framed-IP-Address"]=data[3]
            req["Acct-Session-Id"]=data[8]
            req["Acct-Status-Type"]="Stop"
            req["Acct-Terminate-Cause"] = "User-Request"
	    SendPacket(srv, req)
	    return 0

    else:
        #Usage()
        return -3


class ThreadTCPRequestHandler(SocketServer.StreamRequestHandler):

    def handle(self):
        data = self.rfile.readline().strip()
	tmp = data.split(' ')
	
	if tmp[0] == 'value':
            data = self.rfile.read(int(tmp[1]))
	else:
	    sys.exit(0)

	cur_thread = threading.current_thread()
        data = data.split(' ')
        length = len(data)
	now = str(time.time())
	#print cur_thread.name, data[0],data[1], len(data), now
        if length != 7 and length != 12:
            result = -3
	#    print 'result=', result
            #response = "{}".format(result)
            self.wfile.write(str(result))
        else:
            result=DealData(data)
	    #if "stop" in data:
	    #    print cur_thread.name, 'result stop', result, now
	    #else:
	    #    print cur_thread.name, 'result=', result, now
	    #print 
            #response = "{}".format(str(result))
            #self.request.sendall(response)
	    if data[0] == "auth" or (data[0] == "acct" and data[1] == "start"):
	      #print 'send result'
              self.wfile.write(str(result))

class ThreadeTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

def ForkFunc():
    HOST, PORT = "0.0.0.0", 14000
    global dictionary
    #global dict_client
    dict_client = {}

    dictionary = Dictionary("/usr/local/share/freeradius/dictionary")

    server = ThreadeTCPServer((HOST, PORT), ThreadTCPRequestHandler)
    server.allow_reuse_address = True
    #ip, port = server.server_address

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    server.serve_forever()

    #server.shutdown()
    #server.server_close()
#if __name__ == "__main__":
    #ForkFunc()
def CreateDaemon():

    try:
        if os.fork() > 0: os._exit(0)
    except OSError, error:
        return 'fork #1 failed: %d (%s)' % (error.errno, error.strerror)
        os._exit(1)    
    os.chdir('/')
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0:
            return 'Daemon PID %d' % pid
            os._exit(0)
    except OSError, error:
        return 'fork #2 failed: %d (%s)' % (error.errno, error.strerror)
        os._exit(1)

    sys.stdout.flush()
    sys.stderr.flush()
    si = file("/dev/null", 'r')
    so = file("/dev/null", 'a+')
    se = file("/dev/null", 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    ForkFunc() # function demo

if __name__ == '__main__': 

    if platform.system() == "Linux":
        CreateDaemon()
    else:
        os._exit(0)
