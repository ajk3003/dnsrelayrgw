"""
BSD 3-Clause License
Copyright (c) 2019, Antti Koskimäki, Aalto University, Finland
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import argparse
import multiprocessing
import random
import socket
import socketserver
import struct
import sys
import threading
import time

from multiprocessing import Queue as mQueue
from multiprocessing import Process
from socket import IPPROTO_TCP, TCP_NODELAY

import dns.edns
import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from dnshelperfunctions1 import getDNSInfoUDP, getDNSInfoUDPNoCname
from dnshelperfunctions1 import getDNSInfoTCP, getDNSReplyInfo
"""
This is a custom DNS relay program that uses the dnshelperfunctions file in
addition. The program runs 4 separate processes, where 2 are dedicated to
act as TCP and UDP servers, 1 is for data/query processing and 1 is for
relaying request to the Realm Gateway. Addresses, ports, security options
and limited DNS options can be given as input on the command line when the
program is started. See use the "-h" argument and check the README for
more details.
"""
# TODO: There may be a need for flushing/clearing the dict containing CNAME
# message state information periodically so that it doesn't end up taking too
# much space in memory. In principle this could be just done in a thread in
# the CP process on set time intervals by locking the dict and then clearing
# it. This would cause some ongoing DNS queries to fail, but the respective
# clients could do retries to remedy this.

# Some default buffer values for network connections
SERVUDPBFR = 4096
SERVTCPBFR = 4096
FWDUDPBFR = 4096
FWDTCPBFR = 4096
# ECS subnet mask accuracy - RGW supports properly only sizes 24/16/8
ECSMASK = 24

# Data structures and object locks to facilitate threading
rgwlist = []
cnames = {}
events = {}
P2datamap = {}
lock_cnames = threading.Lock()
lock_events = threading.Lock()
lock_P2datamap = threading.Lock()

# Values that are finally set by argument input on the program start
randomizeRGW = True
forwardECS = True
CNAMEstep = True
TCPstep = True


# Process 1 (UDP server) definition, threads, etc. below:
def process1_UDPsrv(q1, q2, servaddr):
    # tempp
    print("P1 - Starting process 1 - UDP sender & server\n")
    thread1 = P1T1_UDPServer(q1, servaddr)
    thread1.start()
    time.sleep(1)
    thread2 = P1T2_UDPSender(q2, thread1.return_server_socket())
    thread2.start()
    thread2.join()
    thread1.join()
    print("P1 - Exiting process 1...\n")


class P1T1_UDPServer(threading.Thread):

    def __init__(self, q1, addr):
        threading.Thread.__init__(self)
        self.q1 = q1
        self.addr = addr
        self.serversocket = 0
        # tempp
        print("P1T1 - UDP server thread starting\n")

    def run(self):
        server = MyUDPServer(self.q1, self.addr, UDPClientHandler)
        self.serversocket = server.socket
        # tempp
        print("P1T1 - Running UDP server loop forever\n")
        server.serve_forever(5)

    def return_server_socket(self):
        return self.serversocket


class P1T2_UDPSender(threading.Thread):

    def __init__(self, q2, serversocket):
        threading.Thread.__init__(self)
        self.q2 = q2
        self.serversocket = serversocket
        # tempp
        print("P1T2 - UDP Sender Thread starting\n")

    def run(self):
        # tempp
        print("P1T2 - UDP Sender listening loop starting\n")
        while True:
            data = self.q2.get()
            self.serversocket.sendto(data[0], data[1])
            # tempp
            # print("P1T2 - UDP Sender sent reply to client\n")


class UDPClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # tempp
        # print("P1 - UDP Server got data\n")
        self.server.q1.put((self.request[0],
                            self.client_address,
                            -1,
                            0))
        # tempp
        # print("P1T1 - UDP server fwd sg to q1 - handling done\n")


class MyUDPServer(socketserver.UDPServer):

    def __init__(self, q1, *args, **kwargs):
        super(MyUDPServer, self).__init__(*args, **kwargs)
        self.q1 = q1
        # tempp
        print("P1T1 - UDP Server starting\n")


# Process 2 (TCP server) definition, threads, etc. below:
def process2_TCPsrv(q3, q4, servaddr):
    # tempp
    print("P2 - Starting process 2\n")
    if TCPstep == 1:
        tcpserverthread = P2T1_TCPServer(q3, servaddr)
        tcpserverthread.start()
    # tempp
    print("P2 - Starting manager loop")
    while True:
        data = q4.get()
        lock_P2datamap.acquire()
        P2datamap[data[2]] = (data[0], data[1])
        lock_P2datamap.release()
        lock_events.acquire()
        events[data[2]].set()
        lock_events.release()
        # tempp
        # print("P2 - Manager received data, set event and put data to dict\n")
    if TCPstep == 1:
        tcpserverthread.join()
    print("P2 - Exiting process 2\n")


class P2T1_TCPServer(threading.Thread):

    def __init__(self, q3, addr):
        threading.Thread.__init__(self)
        self.q3 = q3
        self.addr = addr
        # tempp
        print("P2T1 - TCP server thread starting\n")

    def run(self):
        server = MyThreadedTCPServer(self.q3,
                                     self.addr,
                                     TCPClientHandler)
        # tempp
        print("P2T1 - Running TCP forever loop\n")
        server.socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        server.serve_forever(5)


class TCPClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # tempp
        # print("P2 - TCP Server received data\n")
        data = self.request.recv(SERVTCPBFR)
        event = threading.Event()
        threadID = threading.current_thread().ident
        events[threadID] = event
        self.server.q3.put((data[2:],
                            self.client_address,
                            threadID,
                            0))
        # tempp
        # print("P2 - TCP server thread x event listening loop\n")
        while True:
            event.wait()
            lock_P2datamap.acquire()
            data = P2datamap[threadID]
            del P2datamap[threadID]
            lock_P2datamap.release()
            lock_events.acquire()
            del events[threadID]
            lock_events.release()
            break
        if data[1] != 0:
            self.request.sendall(struct.pack('!H', len(data[0])) + data[0])
            # tempp
            # print("P2 - TCP server send data back to client\n")
            pass
        else:
            # tempp
            print("P2 - TCP server endend connection, faulty query\n")
            pass


class MyTCPServer(socketserver.TCPServer):

    def __init__(self, q3, *args, **kwargs):
        super(MyTCPServer, self).__init__(*args, **kwargs)
        self.q3 = q3
        # tempp
        print("P2 - TCP Server starting\n")


class MyThreadedTCPServer(socketserver.ThreadingMixIn, MyTCPServer):
    pass


# Process 3 (Central Processing) definition, threads, etc. below:
def process3_CP(q1, q2, q3, q4, q5, q6, scn, mask, ecs):
    # tempp
    print("P3 - Starting process 3\n")
    thread1 = P3T1_UDPH(q1, q2, q5, scn, mask, ecs)
    thread1.start()
    thread2 = P3T2_TCPH(q3, q4, q5)
    thread2.start()
    thread3 = P3T3_Answer(q2, q4, q6)
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()


class P3T1_UDPH(threading.Thread):

    def __init__(self, q1, q2, q5, scn, mask, ecs):
        threading.Thread.__init__(self)
        self.q1 = q1
        self.q2 = q2
        self.q5 = q5
        self.scn = scn
        self.mask = mask
        self.ecs = ecs
        # tempp
        print("P3T1 - CP UDPH thread starting\n")

    def run(self):
        # tempp
        print("P3T1 - CP UDPH thread listening loop starting\n")

        while True:
            data = self.q1.get()
            if ((TCPstep is True) and (CNAMEstep is True)):
                dnsmsg_t = getDNSInfoUDP(data[0],
                                         self.scn,
                                         True,
                                         data[1][0],
                                         self.mask,
                                         self.ecs)
            elif ((TCPstep is False) and (CNAMEstep is True)):
                dnsmsg_t = getDNSInfoUDP(data[0],
                                         self.scn,
                                         False,
                                         data[1][0],
                                         self.mask,
                                         self.ecs)
            elif ((TCPstep is True) and (CNAMEstep is False)):
                dnsmsg_t = getDNSInfoUDPNoCname(data[0],
                                                True,
                                                data[1][0],
                                                self.mask,
                                                self.ecs)
            else:
                dnsmsg_t = getDNSInfoUDPNoCname(data[0],
                                                False,
                                                data[1][0],
                                                self.mask,
                                                self.ecs)
            if dnsmsg_t[1] == 0:
                # tempp
                print("P3T1 - Malformed DNS message, discarding\n")
                pass
            elif dnsmsg_t[1] == 1:
                # tempp
                print("P3T1 - DNS message is not a proper query, discarding\n")
                pass
            elif dnsmsg_t[1] == 2:
                # TODO: choose subnet from dict here and add it to the 4th in
                # tuple
                self.q2.put((dnsmsg_t[0], data[1]))
                # tempp
                # print("P3T1 - CP UDPH thread received and sent data:\n")
                # print("Valid UDP DNS query - replying with trunc.\n")
            elif dnsmsg_t[1] == 3:
                # TODO: choose rgw addr based on subnet, now it's just "0"
                try:
                    lock_cnames.acquire()
                    tempaddr = cnames[dnsmsg_t[2]]
                    del cnames[dnsmsg_t[2]]
                    lock_cnames.release()
                    self.q5.put((dnsmsg_t[0],
                                 data[1],
                                 -1,
                                 dnsmsg_t[3],
                                 dnsmsg_t[4],
                                 tempaddr))

                except KeyError:
                    lock_cnames.release()
                    print("P3T1 - DNS message CNAME not in dict\n")
                    pass
            else:
                self.q5.put((dnsmsg_t[0],
                             data[1],
                             -1,
                             dnsmsg_t[3],
                             dnsmsg_t[4],
                             0))


class P3T2_TCPH(threading.Thread):

    def __init__(self, q3, q4, q5):
        threading.Thread.__init__(self)
        self.q3 = q3
        self.q4 = q4
        self.q5 = q5
        # tempp
        print("P3T2 - CP TCPH thread starting\n")

    def run(self):
        # TODO: change TCP/CNAMEsteps to local variables given as input
        # tempp
        print("P3T2 - CP TCPH thread listening loop starting\n")
        while True:
            data = self.q3.get()

            if CNAMEstep is True:
                dnsmsg_t = getDNSInfoTCP(data[0], True)
            else:
                dnsmsg_t = getDNSInfoTCP(data[0], False)
            if dnsmsg_t[1] == 0:
                self.q4.put((0, 0, data[2], -1))
                # tempp
                print("P3T2 - Malformed DNS message, discarding\n")
                pass
            elif dnsmsg_t[1] == 1:
                self.q4.put((0, 0, data[2], -1))
                # tempp
                print("P3T2 - DNS message is not a proper query, discarding\n")
                pass
            else:
                self.q5.put((dnsmsg_t[0],
                             data[1],
                             data[2],
                             dnsmsg_t[2],
                             dnsmsg_t[3],
                             0))


class P3T3_Answer(threading.Thread):

    def __init__(self, q2, q4, q6):
        threading.Thread.__init__(self)
        self.q2 = q2
        self.q4 = q4
        self.q6 = q6
        # tempp
        print("P3T3 - CP Answer thread starting\n")

    def run(self):
        # TODO: change TCP/CNAMEsteps to local variables given as input
        # tempp
        print("P3T3 - CP Answer thread listening loop starting\n")
        while True:
            data = self.q6.get()
            if ((TCPstep is True) and (CNAMEstep is True)):
                dnsmsg_t = getDNSReplyInfo(data[0], data[4], True, True)
            elif ((TCPstep is True) and (CNAMEstep is False)):
                dnsmsg_t = getDNSReplyInfo(data[0], data[4], True, False)
            elif ((TCPstep is False) and (CNAMEstep is True)):
                dnsmsg_t = getDNSReplyInfo(data[0], data[4], False, True)
            else:
                dnsmsg_t = getDNSReplyInfo(data[0], data[4], False, False)
            if dnsmsg_t[1] == 0:
                # tempp
                print("P3T3 - Malformed DNS answer from RGW, discarding\n")
                pass
            elif dnsmsg_t[1] == 1:
                # tempp
                print("P3T3 - DNS answer from RGW not proper, discarding\n")
                pass
            elif dnsmsg_t[1] == 2:
                lock_cnames.acquire()
                cnames[dnsmsg_t[2]] = data[5]
                lock_cnames.release()
                self.q2.put((data[0], data[1]))
                # tempp
                # print("P3T3 - CP  Answer thread received and sent data:\n")
                # print("Valid UDP Cname reply - forwarding to client UDP.\n")
            elif dnsmsg_t[1] == 4:
                lock_cnames.acquire()
                cnames[dnsmsg_t[2]] = data[5]
                lock_cnames.release()
                self.q4.put((data[0], data[1], data[2]))
                # tempp
                # print("P3T3 - CP  Answer thread received and sent data:\n")
                # print("Valid UDP Cname reply - forwarding to client TCP.\n")
            elif dnsmsg_t[1] == 3:
                self.q2.put((data[0], data[1]))
                # tempp
                # print("P3T3 - CP  Answer thread received and sent data:\n")
                # print("Valid UDP reply - forwarding to client UDP.\n")
            else:
                self.q4.put((data[0], data[1], data[2]))
                # tempp
                # print("P3T3 - CP  Answer thread received and sent data:\n")
                # print("Valid UDP reply - forwarding to client TCP.\n")


# Process 4 (Data Forwarder, UDP) definition, threads, etc. below:
def process4_fwdUDP(q5, q6, dnstimeout, dnstries, rgwaddrlist, randomize):
    # tempp
    print("P4 - Starting process 4\n")
    print("P4 - Starting listening loop\n")
    while True:
        data = q5.get()
        # tempp
        # print("P4 - Creating sender thread\n")
        if randomize:
            if data[5] == 0:
                temp = int(len(rgwaddrlist) * random.random())
                rgwaddr = rgwaddrlist[temp]
            else:
                rgwaddr = data[5]
            P4TX_UDPSender(q6, data, dnstimeout, dnstries, rgwaddr).start()
        else:
            rgwaddr = rgwaddrlist[0]
            P4TX_UDPSender(q6, data, dnstimeout, dnstries, rgwaddr).start()


class P4TX_UDPSender(threading.Thread):

    def __init__(self, q6, data, dnstimeout, dnstries, rgwaddr):
        threading.Thread.__init__(self)
        self.q6 = q6
        self.data = data
        self.dnstimeout = dnstimeout
        self.dnstries = dnstries
        self.rgwaddr = rgwaddr
        # tempp
        # print("P4TX - UDP Sender Thread starting\n")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.dnstimeout)
        # TODO: temprorary, change this when testing with real rgw
        sock.sendto(self.data[0], self.rgwaddr)
        isTO = False
        tempv = 1
        while True:
            try:
                reply, addr = sock.recvfrom(4096)
                break
            except socket.timeout:
                if tempv >= self.dnstries:
                    isTO = True
                    break
                else:
                    tempv += 1
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.dnstimeout)
                    sock.sendto(self.data[0], self.rgwaddr)

        sock.close()
        if isTO:
            print("Timeout for UDP DNS Query to RGW"
                  " address: " + self.rgwaddr[0] + "\n")
        else:
            self.q6.put((reply,
                        self.data[1],
                        self.data[2],
                        self.data[3],
                        self.data[4],
                        addr))
        # tempp
        # print("P4TX - Send and received data, forwarding to CP\n")


# TODO:
# (Optional) Process 4 (Data Forwarder, TCP) definition, threads, etc. below:
def process4_fwdTCP(q5, q6):
    pass


# Functions below for help parsing valid command line arguments.
class saddrAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for IP address validity."""
        try:
            socket.inet_aton(values)
        except socket.error:
            parser.error("IP address should be in valid a.b.c.d IPv4 format.")

        setattr(namespace, self.dest, values)


class sportAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for port validity."""
        if ((values < 1) or (values > 65535)):
            parser.error("Port numbers shoud be between 1 and 65535.")

        setattr(namespace, self.dest, values)


class ecsAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for yes or no value validity."""
        if not ((values == "yes") or (values == "no")):
            parser.error("ECS option should be yes or no.")

        setattr(namespace, self.dest, values)


class tcpAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for yes or no value validity."""
        if not ((values == "yes") or (values == "no")):
            parser.error("TCP option should be yes or no.")

        setattr(namespace, self.dest, values)


class cnameAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for yes or no value validity."""
        if not ((values == "yes") or (values == "no")):
            parser.error("CNAME option should be yes or no.")

        setattr(namespace, self.dest, values)


class randrgwAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for yes or no value validity."""
        if not ((values == "yes") or (values == "no")):
            parser.error("Randomize RGW option should be yes or no.")

        setattr(namespace, self.dest, values)


class dnstoAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for int validity."""
        if ((values < 1) or (values > 120)):
            parser.error("Timeout should be between 1 and 120 seconds.")

        setattr(namespace, self.dest, values)


class dnstryAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for int validity."""
        if ((values < 0) or (values > 30)):
            parser.error("Additional attempts should be between 0 and 30.")

        setattr(namespace, self.dest, values)


class rgwsAction(argparse.Action):
    """Argparse action."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Check for addr/port validity."""
        if values:
            ipvalue = True
            for x in values:
                if ipvalue is True:
                    ipvalue = False
                    try:
                        socket.inet_aton(x)
                    except socket.error:
                        parser.error("IP address should be in valid a.b.c.d" +
                                     " IPv4 format.")
                else:
                    ipvalue = True
                    try:
                        tempx = int(x)
                    except ValueError:
                        parser.error("Port number shoud be a positive integer")

                    if ((tempx < 1) or (tempx > 65535)):
                        parser.error("Port numbers shoud be between" +
                                     " 1 and 65535.")

            if ipvalue is False:
                parser.error("Address missing a respective port value")

        else:
            parser.error("Destination RGW list empty.")

        setattr(namespace, self.dest, values)


# Main function below
def main():
    """Run the main program."""
    parser = argparse.ArgumentParser(description="Custom DNS relay server")
    parser.add_argument("-saddr",
                        "--dns_relay_server_address",
                        action=saddrAction,
                        help="Valid IPv4 address for the DNS relay server",
                        default="127.0.0.1")
    parser.add_argument("-sport",
                        "--dns_relay_server_port",
                        help="Valid port for the DNS relay server",
                        action=sportAction,
                        type=int,
                        default=53)
    parser.add_argument("-ecs",
                        "--forward_ecs",
                        action=ecsAction,
                        help="Forward ECS with DNS - yes/no",
                        default="yes")
    parser.add_argument("-tcp",
                        "--use_tcp_security_step",
                        action=tcpAction,
                        help="Use TCP DNS security step - yes/no",
                        default="yes")
    parser.add_argument("-cname",
                        "--use_cname_security_step",
                        action=cnameAction,
                        help="Use CNAME DNS security step - yes/no",
                        default="yes")
    parser.add_argument("-randrgw",
                        "--randomize_destination_rgw",
                        action=randrgwAction,
                        help="Randomize destination RGW - yes/no",
                        default="yes")
    parser.add_argument("-cnamestr",
                        "--rgw_cname_string_component",
                        help="Leftmost part of dest. RGW dns-cname-soa config",
                        default="cname")
    parser.add_argument("-dnsto",
                        "--dns_timeout",
                        help="DNS request timeout towards RGW in seconds",
                        action=dnstoAction,
                        type=int,
                        default=3)
    parser.add_argument("-dnstry",
                        "--dns_request_attempts",
                        help="Max. DNS request attempts towards RGW",
                        action=dnstryAction,
                        type=int,
                        default=3)
    parser.add_argument('-rgws',
                        '--rgws_list',
                        nargs='+',
                        action=rgwsAction,
                        help='List of RGW address (str) and port (int) pairs')

    args = parser.parse_args()
    print("Starting the custom DNS relay server...\n")
    print("Server IP address and port: {}, {}\n".
          format(args.dns_relay_server_address,
                 str(args.dns_relay_server_port)))

    servaddr = (args.dns_relay_server_address, args.dns_relay_server_port)

    if(args.forward_ecs == "yes"):
        print("Client subnet forwarding with DNS ECS is ON.\n")
        forwardECS = True
    else:
        print("Client subnet forwarding with DNS ECS is OFF.\n")
        forwardECS = False

    if(args.use_tcp_security_step == "yes"):
        print("DNS TCP security step is ON.\n")
        TCPstep = True
    else:
        print("DNS TCP security step is OFF.\n")
        TCPstep = False

    if(args.use_cname_security_step == "yes"):
        print("DNS CNAME security step is ON.\n")
        CNAMEstep = True
    else:
        print("DNS CNAME security step is OFF.\n")
        CNAMEstep = False

    if(args.randomize_destination_rgw == "yes"):
        print("Destination RGW randomization is ON.\n")
        randomizeRGW = True
    else:
        print("Destination RGW randomization is OFF.\n")
        randomizeRGW = False

    print("CNAME string component in use: ")
    servicecname = args.rgw_cname_string_component
    print(servicecname)
    print("\n")

    dnstimeout = args.dns_timeout
    dnstries = args.dns_request_attempts
    print("DNS request timeout in seconds: ")
    print(str(dnstimeout))
    print("\n")
    print("Maximum additional DNS request attempts: ")
    print(str(dnstries))
    print("\n")

    # Populating the destination RGW list
    if args.rgws_list:
        tempaddr = 0
        tempport = 0
        ipvalue = True
        for x in args.rgws_list:
            if ipvalue is True:
                ipvalue = False
                tempaddr = x
            else:
                ipvalue = True
                tempport = x
                rgwlist.append((tempaddr, int(tempport)))
        print("Following destination RGWs were given:\n")
        for x in rgwlist:
            print(x)
        print("\n")
    else:
        print("No destination RGWs given, using the default: \n")
        print("addr 127.0.0.1 port 54\n ")
        rgwlist.append(("127.0.0.1", 54))

    print("Server serves forever; exit by pressing CTRL-C")

    # Creating queues for communication between processes
    # p1 -> p3 (From UDP _server_ to Data handler)
    q1 = mQueue()

    # p3 -> p1 (From Data handler to clientside UDP _sender_)
    q2 = mQueue()

    # p2 -> p3 (From TCP server to data handler)
    q3 = mQueue()

    # p3 -> p2 (From data handler to TCP server)
    q4 = mQueue()

    # p3 -> p4 (From data handler to rgwside UDP/TCP sender)
    q5 = mQueue()

    # p4 -> p3 (From rgwside UDP/TCP sender to data handler)
    q6 = mQueue()

    p1 = Process(target=process1_UDPsrv, args=(q1, q2, servaddr))
    p2 = Process(target=process2_TCPsrv, args=(q3, q4, servaddr))
    p3 = Process(target=process3_CP, args=(q1,
                                           q2,
                                           q3,
                                           q4,
                                           q5,
                                           q6,
                                           servicecname,
                                           ECSMASK,
                                           forwardECS))
    p4 = Process(target=process4_fwdUDP, args=(q5,
                                               q6,
                                               dnstimeout,
                                               dnstries,
                                               rgwlist,
                                               randomizeRGW))
    p1.start()
    p2.start()
    p3.start()
    p4.start()
    try:
        p1.join()
        p2.join()
        p3.join()
        p4.join()

    except KeyboardInterrupt:
        p1.terminate()
        p2.terminate()
        p3.terminate()
        p4.terminate()
        # TODO: Remember to flush IP tables
        print("--Exiting Custom DNS server program (Ctrl-C)--\n")
        sys.exit()

    print("Exiting Custom DNS server program...\n")


if __name__ == "__main__":
    main()
