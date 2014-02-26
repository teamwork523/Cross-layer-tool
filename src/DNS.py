#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/25/2013

Copyright (c) 2012-2014 RobustNet Research Group, University of Michigan.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by the RobustNet Research Group, University of Michigan.  The name of the
RobustNet Research Group, University of Michigan may not 
be used to endorse or promote products derived
from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

DNS parsing and create a map between IP packets and URL

Thanks to Paul Chakravarti (paul.chakravarti@gmail.com) for dnslib
http://bitbucket.org/paulc/dnslib/
"""

import const
import sys
# TODO: append the current library
import lib.dnslib.dns as dns

class DNS(object):
    """
    1. ipToURLMap: A map between ip and URLs
    """
    def __init__(self, entryList):
        self.entryToDNS = {}
        
        for entry in entryList:
            if entry.udp["src_port"] == const.DNS_PORT or \
               entry.udp["dst_port"] == const.DNS_PORT:
                start = const.Payload_Header_Len + entry.ip["header_len"] + \
                        const.UDP_Header_Len
                dns_query = "".join(entry.hex_dump["payload"][start:])

                # use the DNS library to parse the packet
                d = dns.DNSRecord.parse(dns_query.decode('hex'))
                
                self.entryToDNS[entry] = d

    # get the ip to URL map
    # ip: [list of URLs]
    def getIpToURLMap(self):
        ipToURLMap = {}

        for d in self.entryToDNS.values():
            # check whether the DNS is a query or response
            if d.header.get_qr() == const.DNS_RESPONSE:
                ip = d.rr[d.header.a - 1].rdata.data
                ipToURLMap[ip] = []
                for rrIndex in range(d.header.a):
                    try:
                        ipToURLMap[ip].append(str(d.rr[rrIndex].rname))
                    except AttributeError:
                        print >> sys.stderr, "ERROR: Invalid parsing during \n" + str(d)

        return ipToURLMap

