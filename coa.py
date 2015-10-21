#!/usr/bin/python

import socket
import select 
from pyrad import dictionary, packet, server

COAPORT=3799

class CoaServer(server.Server):

    def __init__(self, addresses=[], authport=1812, acctport=1813, hosts=None,
            dict=None):
        self.sockfds = []

    def _HandleAuthPacket(self, pkt):
        server.Server._HandleAuthPacket(self, pkt)

        print "Received an authentication request"
        print "Attributes: "
        for attr in pkt.keys():
            print "%s: %s" % (attr, pkt[attr])
        print

        reply=self.CreateReplyPacket(pkt)
        reply.code=packet.AccessAccept
        self.SendReplyPacket(pkt.fd, reply)

    def _HandleAcctPacket(self, pkt):
        server.Server._HandleAcctPacket(self, pkt)

        print "Received an accounting request"
        print "Attributes: "
        for attr in pkt.keys():
            print "%s: %s" % (attr, pkt[attr])
        print

        reply=self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def BindToAddress(self, coaport):
        """Add an address to listen to.
        An empty string indicated you want to listen on all addresses.

        :param addr: IP address to listen on
        :type  addr: string
        """
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #sockfd.bind((addr, 2000))
        sockfd.bind(('0.0.0.0', coaport))

        self.sockfds.append(sockfd)
        #self.acctfds.append(acctfd)

    def _ProcessInput(self, fdo):
        print'ProcessInput'

    def _PrepareSockets(self):
        """Prepare all sockets to receive packets.
        """ 
        for fd in self.sockfds:
            self._fdmap[fd.fileno()] = fd
            self._poll.register(fd.fileno(),
                select.POLLIN | select.POLLPRI | select.POLLERR)
        self._reasockfds = list(map(lambda x: x.fileno(), self.sockfds))

    def Run(self):
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them.
        """
        self._poll = select.poll()
        self._fdmap = {}
        self._PrepareSockets()

        while 1:
            for (fd, event) in self._poll.poll():
                if event == select.POLLIN:
                    try:
                        fdo = self._fdmap[fd]
                        self._ProcessInput(fdo)
                    except server.ServerPacketError as err:
                        logger.info('Dropping packet: ' + str(err))
                    except packet.PacketError as err:
                        logger.info('Received a broken packet: ' + str(err))
                else:
                    logger.error('Unexpected event in server main loop')



srv=CoaServer(dict=dictionary.Dictionary("/usr/local/share/freeradius/dictionary"))
#srv.hosts["127.0.0.1"]=server.RemoteHost("127.0.0.1",
                                         #"testing123",
                                         #"localhost")
srv.BindToAddress(COAPORT)
srv.Run()
