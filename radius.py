#!/usr/bin/env python

import random, socket, sys
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import time

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
            #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
            print -1
    for i in range(4):
            try:
                    addr[i]=int(addr[i]) 
            except:
                      #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
		    print -1
            if addr[i]<=255 and addr[i]>=0:   
                    pass
            else:
		    #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
		    print -1
            i+=1

def SendPacket(srv, req):
    try:
        return srv.SendPacket(req)
    except pyrad.client.Timeout:
        #print "RADIUS server does not reply"
        print -1
    except socket.error, error:
        #print "Network error: " + error[1]
        #sys.exit(1)
        print -1

def main(argv):

    acct_list = ['start', 'update', 'stop']

    if len(argv) == 7 and argv[0] == 'auth':
        # argv[1] nasip
        # argv[2] userip
        # argv[3] username
        # argv[4] password
        # argv[5] radius addr
        # argv[6] radius secret
        check_ip(argv[1])
        check_ip(argv[2])
        srv=Client(server=argv[5],
               secret=argv[6],
               dict=Dictionary("/usr/local/share/freeradius/dictionary"))

        req=srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                 User_Name=argv[3])

        req["User-Password"]      = req.PwCrypt(argv[4])
        req["NAS-IP-Address"]     = argv[1]
        #req["NAS-Port"]           = 0
        #req["Service-Type"]       = "Login-User"
        #req["NAS-Identifier"]     = "trillian"
        #req["Called-Station-Id"]  = "00-04-5F-00-0F-D1"
        #req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
        req["Framed-IP-Address"]  = argv[2]

        reply = SendPacket(srv, req)

        if reply.code==pyrad.packet.AccessAccept:
            if reply:
                print reply['Acct-Interim-Interval'][0]
            else:
                print 0
        else:
            print -2
    elif len(argv) == 12 and argv[0] == 'acct' and argv[1] in acct_list:
        # argv[1] auth type
        # argv[2] nasip
        # argv[3] userip
        # argv[4] usermac
        # argv[5] inputotect
        # argv[6] outputotect
        # argv[7] acctsessiontime
        # argv[8] acctsessionid
        # argv[9] username
        # argv[10] radius addr
        # argv[11] radius secret
        srv=Client(server=argv[10],
                   secret=argv[11],
                   dict=Dictionary("/usr/local/share/freeradius/dictionary"))

        req=srv.CreateAcctPacket(User_Name=argv[9])

        if argv[1] == 'start':
            req["NAS-IP-Address"]=argv[2]
            #req["NAS-Port"]=0
            #req["NAS-Identifier"]="trillian"
            #req["Called-Station-Id"]="00-04-5F-00-0F-D1"
            req["Calling-Station-Id"]=argv[4]
            req["Framed-IP-Address"]=argv[3]
	    acctSessionId = ''.join(argv[4].split(':'))+str(time.time())
            req["Acct-Session-Id"]=acctSessionId
            req["Acct-Status-Type"]="Start"
	    SendPacket(srv, req)
	    print  acctSessionId
        elif argv[1] == 'update':
            req["NAS-IP-Address"]=argv[2]
            req["Acct-Input-Octets"] = int(argv[5])
            req["Acct-Output-Octets"] = int(argv[6])
            req["Acct-Session-Time"] = int(argv[7])
            req["Calling-Station-Id"]=argv[4]
            req["Framed-IP-Address"]=argv[3]
            req["Acct-Session-Id"]=argv[8]
            req["Acct-Status-Type"]="Interim-Update"
	    SendPacket(srv, req)
            print 0
        else:
            req["NAS-IP-Address"]=argv[2]
            req["Acct-Input-Octets"] = int(argv[5])
            req["Acct-Output-Octets"] = int(argv[6])
            req["Acct-Session-Time"] = int(argv[7])
            req["Calling-Station-Id"]=argv[4]
            req["Framed-IP-Address"]=argv[3]
            req["Acct-Session-Id"]=argv[8]
            req["Acct-Status-Type"]="Stop"
            req["Acct-Terminate-Cause"] = "User-Request"
	    SendPacket(srv, req)
            print 0

    else:
        Usage()


if __name__ == '__main__':
    main(sys.argv[1:])

