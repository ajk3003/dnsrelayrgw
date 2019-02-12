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
import multiprocessing
import random
import socket
import socketserver
import struct
import sys
import threading
import time
import dns.message
import dns.edns
import dns.name
from socket import IPPROTO_TCP, TCP_NODELAY

from multiprocessing import Queue as mQueue
from multiprocessing import Process
"""
This program is a simple DNS relay for forwarding DNS queries to some DNS
server further in the DNS system. This relay can add ECS client subnet
information to the DNS messages it handles. The parameters for the program
can be set on modifying the global variables below.
"""

# temp default values for variables below
# TODO: adjust and/or put argparse input instead
SERVADDR = ("127.0.0.1", 53)
SERVUDPBFR = 4096
SERVTCPBFR = 4096
CDNSADDR = ("127.0.0.1", 54)
FWDUDPBFR = 4096
FWDTCPBFR = 4096
ECSMASK = 24
DNSTIMEOUT = 3
DNSTRIES = 3

addECS = False

clients = {}
newids = {}

# temp types
# 0 - UDP query
# 1 - UDP answer - normal
# 2 - TCP query
# 3 - TCP answer - normal
# 4 - UDP query for CNAME
# 5 - UDP CNAME-type answer
# 6 - TCP query for CNAME
# 7 - TCP CNAME-type answer
# 8 - UDP answer with trunc flag (resend with TCP)


# Process 1 (UDP server) definition, threads, etc. below:
def process1_UDPsrv(q1, q2):
    # tempp
    print("P1 - Starting process 1 - UDP sender & server\n")
    thread1 = P1T1_UDPServer(q1, SERVADDR)
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
        # print(self.request[0])
        # print(" from ")
        # print(self.client_address)
        self.server.q1.put((self.request[0], self.client_address))
        # tempp
        # print("P1T1 - UDP server fwd sg to q1 - handling done\n")


class MyUDPServer(socketserver.UDPServer):

    def __init__(self, q1, *args, **kwargs):
        super(MyUDPServer, self).__init__(*args, **kwargs)
        self.q1 = q1
        # tempp
        print("P1T1 - UDP Server starting\n")


# Process 3 (Central Processing) definition, threads, etc. below:
def process2_CP(q1, q2, q3, q4, q5, q6, ecs, mask):
    # tempp
    print("P2 - Starting process 2\n")
    thread1 = P2T1_step1Handler(q1, q3, ecs, mask)
    thread1.start()
    thread2 = P2T2_tcpAnswHandler(q2, q3, q6)
    thread2.start()
    thread3 = P2T3_udpAnswHandler(q2, q3, q4, q5)
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()


class P2T1_step1Handler(threading.Thread):

    def __init__(self, q1, q3, ecs, mask):
        threading.Thread.__init__(self)
        self.q1 = q1
        self.q3 = q3
        self.ecs = ecs
        self.mask = mask
        # tempp
        print("P2T1 - CP  step1Handler thread starting\n")

    def run(self):
        # tempp
        print("P2T1 - CP step1Handler thread listening loop starting\n")
        while True:
            data = self.q1.get()
            dnsmsg = dns.message.from_wire(data[0])
            if self.ecs:
                tmp_optionlist = []
                tmp_optionlist.append(dns.edns.ECSOption(data[1][0],
                                                         self.mask,
                                                         0))
                dnsmsg.use_edns(0, 0, 1280, 1280, tmp_optionlist)
            self.q3.put((dnsmsg.to_wire(), data[1], dnsmsg.id, 1))


class P2T2_tcpAnswHandler(threading.Thread):

    def __init__(self, q2, q3, q6):
        threading.Thread.__init__(self)
        self.q2 = q2
        self.q3 = q3
        self.q6 = q6
        # tempp
        print("P2T2 - CP tcpAnswHandler thread starting\n")

    def run(self):
        # tempp
        print("P2T2 - CP tcpAnswHandler thread listening loop starting\n")
        while True:
            data = self.q6.get()
            dnsmsg = dns.message.from_wire(data[0])
            isCname = False
            for x in dnsmsg.answer:
                tmp_arr = x.to_text().split()
                if "CNAME" in tmp_arr:
                    cnaddr = (tmp_arr[tmp_arr.index("CNAME") + 1])[:-1]
                    isCname = True
                    break
            if isCname:
                dnsquery = dns.message.make_query(cnaddr,
                                                  dns.rdatatype.A)
                self.q3.put((dnsquery.to_wire(), data[1], data[2], 3))
            else:
                dnsmsg.id = data[2]
                self.q2.put((dnsmsg.to_wire(), data[1]))


class P2T3_udpAnswHandler(threading.Thread):

    def __init__(self, q2, q3, q4, q5):
        threading.Thread.__init__(self)
        self.q2 = q2
        self.q3 = q3
        self.q4 = q4
        self.q5 = q5
        # tempp
        print("P2T3 - CP udpAnswHandler thread starting\n")

    def run(self):
        # tempp
        print("P2T3 - CP udpAnswerHandler thread listening loop starting\n")
        while True:
            data = self.q4.get()
            dnsmsg = dns.message.from_wire(data[0])
            if (dnsmsg.flags & (1 << 9)):
                dnsmsg.flags = dnsmsg.flags & 0b0111110101111111
                dnsmsg.id = int(65535 * random.random()) + 1
                self.q5.put((dnsmsg.to_wire(), data[1], data[2], 2))
            else:
                isCname = False
                for x in dnsmsg.answer:
                    tmp_arr = x.to_text().split()
                    if "CNAME" in tmp_arr:
                        cnaddr = (tmp_arr[tmp_arr.index("CNAME") + 1])[:-1]
                        isCname = True
                        break
                if isCname:

                    dnsquery = dns.message.make_query(cnaddr,
                                                      dns.rdatatype.A)
                    self.q3.put((dnsquery.to_wire(), data[1], data[2], 2))
                else:

                    dnsmsg.id = data[2]
                    self.q2.put((dnsmsg.to_wire(), data[1]))


# Process 3 - Sender thread towards CDNS below:
def process3_UDPsend(q3, q4, addr, timeout, tries):
    # tempp
    print("P3 - Starting process 3\n")
    print("P3 - Starting listening loop\n")
    while True:
        data = q3.get()
        # tempp
        # print("P3 - Creating sender thread\n")
        P3TX_Sender(q4, data, addr, timeout, tries).start()


class P3TX_Sender(threading.Thread):

    def __init__(self, q4, data, addr, timeout, tries):
        threading.Thread.__init__(self)
        self.q4 = q4
        self.data = data
        self.cdnsaddr = addr
        self.timeout = timeout
        self.tries = tries
        # tempp
        # print("P3TX - Sender Thread starting\n")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(self.data[0], self.cdnsaddr)
            reply, addr = sock.recvfrom(2048)
            sock.close()
            self.q4.put((reply, self.data[1], self.data[2]))
        except socket.timeout:
            sock.close()
            print("UDP sender socket timeout\n")

        # tempp
        # print("P3TX - Send and received data, forwarding to CP (q4)\n")


def process4_TCPsend(q5, q6, addr, timeout, tries):
    # tempp
    print("P4 - Starting process 4\n")
    print("P4 - Starting listening loop\n")
    while True:
        data = q5.get()
        # tempp
        # print("P4 - Creating sender thread\n")
        P4TX_Sender(q6, data, addr, timeout, tries).start()


class P4TX_Sender(threading.Thread):

    def __init__(self, q6, data, addr, timeout, tries):
        threading.Thread.__init__(self)
        self.q6 = q6
        self.data = data
        self.addr = addr
        self.timeout = timeout
        self.tries = tries
        # tempp
        # print("P4TX - Sender Thread starting\n")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(self.addr)
            sock.sendall(struct.pack('!H', len(self.data[0])) + self.data[0])
            reply = sock.recv(2048)
            self.q6.put((reply[2:], self.data[1], self.data[2]))
            sock.close()
        except socket.timeout:
            sock.close()
            print("TCP sender socket timeout\n")
        # tempp
        # print("P4TX - Send and received data, forwarding to CP (q6)\n")


def main():
    # TODO: Argparse input

    # p1 -> p2
    q1 = mQueue()
    # p2 -> p1
    q2 = mQueue()
    # p2 -> p3
    q3 = mQueue()
    # p3 -> p2
    q4 = mQueue()
    # p2 -> p4
    q5 = mQueue()
    # p4 -> p2
    q6 = mQueue()

    p1 = Process(target=process1_UDPsrv, args=(q1, q2,))
    p2 = Process(target=process2_CP, args=(q1,
                                           q2,
                                           q3,
                                           q4,
                                           q5,
                                           q6,
                                           addECS,
                                           ECSMASK))
    p3 = Process(target=process3_UDPsend, args=(q3,
                                                q4,
                                                CDNSADDR,
                                                DNSTIMEOUT,
                                                DNSTRIES))
    p4 = Process(target=process4_TCPsend, args=(q5,
                                                q6,
                                                CDNSADDR,
                                                DNSTIMEOUT,
                                                DNSTRIES))
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
        print("--Exiting public DNS server program (Ctrl-C)--\n")
        sys.exit()

    print("Exiting public DNS server program...\n")


if __name__ == "__main__":
    main()
