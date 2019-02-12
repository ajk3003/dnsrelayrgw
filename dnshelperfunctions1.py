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
import dns.edns
import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

"""
This is a helper module for the custom DNS relay program. This code contains
mainly functions to parse, check and validate DNS messages with the help of
dnspython library. For more details check the main program code and README.
"""
# giveDNSInfo returns a tuple with the following:
#
# ( dns message object (0 if not needed),
#   resultcode,
#   randomized CNAME string in question section of query (0 if not there),
#   client subnet (0 if no edns client subnet info),
#   dns message id (0 if not needed),
# )
#
# Specific values in tuple are 0 if not applicable/not found/error occured
#
# result codes:
# 0 - Malformed message overall, discard & no reply
# 1 - Problematic DNS query (wrong opcode, etc), discard & no reply
# 2 - Valid normal query, send truncated reply
# 3 - Valid normal query for a CNAME address, forward to rgw
# 4 - Valid normal query, forward to rgw


def getDNSInfoUDP(data, service_cname, mode, caddr, mask, ecs):

    try:
        dnsmsg = dns.message.from_wire(data)
        if ((dnsmsg.opcode() != dns.opcode.QUERY) or
           (bool(dnsmsg.question) is False)):
            return (0, 1)

        # TODO: may use subnetinfo with ratelimiting at this stage
        # subnetinfo = 0
        # if (bool(dnsmsg.options) is not False):
        #     for x in dnsmsg.options:
        #         if x.otype == 8:
        #             subnetinfo = str(x.address)
        #             break
        # TODO: add subnet info to return in case of use CNAME but no TCP

        isCname = False
        for x in dnsmsg.question:
            tmp_arr = x.to_text().split()
            tmp_addr = tmp_arr[0].split(".")
            if service_cname in tmp_addr:
                isCname = True
                break
        if (((isCname is True) and (mode is True)) or (mode is False)):
            ecs_present = False
            for x in dnsmsg.options:
                if x.otype == 8:
                    ecs_present = True
                    break
            if ecs_present is False:
                if dnsmsg.options:
                    tmp_opt = dns.edns.ECSOption(caddr, mask, 0)
                    dnsmsg.options.append(tmp_opt)
                    dnsmsg.use_edns(0, 0, 1280, 1280, dnsmsg.options)
                else:
                    tmp_opt = dns.edns.ECSOption(caddr, mask, 0)
                    tmp_optionlist = []
                    tmp_optionlist.append(tmp_opt)
                    dnsmsg.use_edns(0, 0, 1280, 1280, tmp_optionlist)
        if mode:
            if isCname:
                # the tmp_addr[0] should be checked if it exists on dict,
                # after that, the msg can be forwarded to rgw or discarded
                return (dnsmsg.to_wire(), 3, tmp_addr[0], 0, dnsmsg.id)

            else:
                dnsmsg.flags = dnsmsg.flags | 0b1000001000000000
                return (dnsmsg.to_wire(), 2)

        else:
            if isCname:
                # the tmp_addr[0] should be checked if it exists on dict,
                # after that, the msg can be forwarded to rgw or discarded
                return (dnsmsg.to_wire(), 3, tmp_addr[0], 0, dnsmsg.id)

            else:
                return (dnsmsg.to_wire(), 4, 0, 0, dnsmsg.id)

    except (dns.message.ShortHeader, dns.message.TrailingJunk,
            dns.message.BadEDNS, dns.exception.FormError) as error:
        return (0, 0)


# Same principle as with getDNSInfoUDP()
def getDNSInfoUDPNoCname(data, mode, caddr, mask, ecs):
    try:
        dnsmsg = dns.message.from_wire(data)
        if ((dnsmsg.opcode() != dns.opcode.QUERY) or
           (bool(dnsmsg.question) is False)):
            return (0, 1)

        # TODO: may use subnetinfo with ratelimiting at this stage
        # subnetinfo = 0
        # if (bool(dnsmsg.options) is not False):
        #     for x in dnsmsg.options:
        #         if x.otype == 8:
        #             subnetinfo = str(x.address)
        #             break
        # TODO: add subnet info to return in case of no TCP

        if mode:
            dnsmsg.flags = dnsmsg.flags | 0b1000001000000000
            return (dnsmsg.to_wire(), 2)

        else:
            if ecs:
                ecs_present = False
                for x in dnsmsg.options:
                    if x.otype == 8:
                        ecs_present = True
                        break
                if ecs_present is False:
                    if dnsmsg.options:
                        tmp_opt = dns.edns.ECSOption(caddr, mask, 0)
                        dnsmsg.options.append(tmp_opt)
                        dnsmsg.use_edns(0, 0, 1280, 1280, dnsmsg.options)
                    else:
                        tmp_opt = dns.edns.ECSOption(caddr, mask, 0)
                        tmp_optionlist = []
                        tmp_optionlist.append(tmp_opt)
                        dnsmsg.use_edns(0, 0, 1280, 1280, tmp_optionlist)
            return (dnsmsg.to_wire(), 4, 0, 0, dnsmsg.id)

    except (dns.message.ShortHeader, dns.message.TrailingJunk,
            dns.message.BadEDNS, dns.exception.FormError) as error:
        return (0, 0)


# giveDNSInfoTCP returns a tuple with the following:
#
# ( dns message object (0 if not needed),
#   resultcode,
#   client subnet (0 if no edns client subnet info),
#   dns message id (0 if not needed),
#   CNAME step in use or not (True/False)
# )
#
# Specific values in tuple are 0 if not applicable/not found/error occured
#
# result codes:
# 0 - Malformed message overall, discard & no reply
# 1 - Problematic DNS query (wrong opcode, etc), discard & no reply
# 4 - Valid normal query, forward to rgw
def getDNSInfoTCP(data, mode):

    try:
        dnsmsg = dns.message.from_wire(data)
        if ((dnsmsg.opcode() != dns.opcode.QUERY) or
           (bool(dnsmsg.question) is False)):
            return (0, 1)
        # TODO: add subnet info chekcing/insertion
        # subnetinfo = 0
        # if (bool(dnsmsg.options) is not False):
        #    for x in dnsmsg.options:
        #        if x.otype == 8:
        #            subnetinfo = str(x.address)
        #            break
        else:
            return (dnsmsg.to_wire(), 4, 0, dnsmsg.id)

    except (dns.message.ShortHeader, dns.message.TrailingJunk,
            dns.message.BadEDNS, dns.exception.FormError) as error:
        return (0, 0)


# getDNSReplyInfo returns a tuple with the following:
#
# (
#   dnsmessage if needed (0 usually),
#   resultcode,
#   CNAME reply string to be added to the dict (if applicable),
# )
#
# Specific values in tuple are 0 if not applicable/not found/error occured
#
# result codes:
# 0 - Malformed message overall, discard & no reply
# 1 - Problematic DNS query (wrong opcode, etc), discard & no reply
# 2 - Valid UDP reply with CNAME data, fwd to UDP
# 3 - Valid UDP reply
# 4 - Valid UDP reply with CNAME data, fwd to TCP
# 5 - Valid UDP reply, fwd to TCP
def getDNSReplyInfo(data, msgid, tcpstep, cnamestep):
    try:
        dnsmsg = dns.message.from_wire(data)
        if ((dnsmsg.opcode() != dns.opcode.QUERY) or
           (bool(dnsmsg.question) is False) or
           (msgid != dnsmsg.id)):
            return (0, 1)
        # TODO: add subnet info checking/insertion if needed
        # subnetinfo = 0
        # if (bool(dnsmsg.options) is not False):
        #    for x in dnsmsg.options:
        #        if x.otype == 8:
        #            subnetinfo = str(x.address)
        #            break
        if cnamestep:
            isCname = False
            for x in dnsmsg.answer:
                tmparr = x.to_text().split()
                if "CNAME" in tmparr:
                    cnstr = (tmparr[tmparr.index("CNAME") + 1].split("."))[0]
                    isCname = True
                    break
            if ((isCname is True) and (tcpstep is True)):
                return (0, 4, cnstr)
            elif ((isCname is True) and (tcpstep is False)):
                return (0, 2, cnstr)
            else:
                return (0, 3)
        else:
            if tcpstep is True:
                return (0, 5)
            else:
                return (0, 3)

    except (dns.message.ShortHeader, dns.message.TrailingJunk,
            dns.message.BadEDNS, dns.exception.FormError) as error:
        return (0, 0)
