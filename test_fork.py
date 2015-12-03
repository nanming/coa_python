#!/usr/bin/python

import os, time


source = 10

try:
    pid = os.fork()

    #while True:
    if pid == 0:
        print "this is child process."
        source = source - 1
        time.sleep(5)
    else:
        print "this is parent process."
        time.sleep(5)
        #os._exit(0)
    print source
except OSError, e:
    pass
