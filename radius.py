#!/usr/bin/env python

import random, socket, sys
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
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


Usage()
