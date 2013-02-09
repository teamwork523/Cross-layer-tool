#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
Define QCAT log entry class
"""

import re
import calendar
from datetime import datetime
import const

# define constant
Payload_Header_Len = 8
IP_Header_Len = 20

class QCATEntry:
    """
    Each Entry should have three part:
    1. Title: timestamp, log_id (i.e. 0x4125), log_type (i.e. WCDMA RRC States)
    2. Detail: specific type information
    3. Hex_dump: detailed hex informaiton
    """
    def __init__(self, title, detail, hex_dump):
        self.title = title
        self.detail = detail
        self.hex_dump = hex_dump
        # timestamp: [unix_timestamp, milliseconds]
        self.timestamp = []
        # log id in integer
        self.logID = None
        # RRC id
        self.rrcID = None 
        # ip information
        self.ip = {"tlp_id": None, \
                   "seg_num": None, \
                   "final_seg": None, \
                   "src_ip": None, \
                   "dst_ip": None, \
                   "header_len": None, \
                   "total_len": None}
        # TCP information
        # TODO: add more tcp fields
        self.tcp = {"src_port": None, \
                    "dst_port": None, \
                    "CWR": None, \
                    "ECE": None, \
                    "URG": None, \
                    "ACK": None, \
                    "PSH": None, \
                    "RST": None, \
                    "SYN": None, \
                    "FIN": None}
        self.udp = {"src_port": None, \
                    "dst_port": None, \
                    "total_len": None}
        # order matters
        self.__procTitle()
        self.__procDetail()
        self.__procHexDump()
        self.__extractProtocolInfo()

    def __procTitle(self):
        # print "Process Titile"
        if self.title != "":
            tList = self.title.split()
            # TODO: Support time difference
            # Parse the timestamp, only support UTC right now
            year = (int)(tList[0])
            month = (int)(const.MONTH_MAP[tList[1].lower()])
            day = (int)(tList[2])
            [secsList, millisec] = tList[3].split('.')
            [hour, minutes, sec] = secsList.split(':')
            dt = datetime(year, month, day, (int)(hour), (int)(minutes), (int)(sec))
            unixTime = calendar.timegm(dt.utctimetuple())
            self.timestamp = [unixTime, (int)(millisec)]
            # print self.timestamp
            # Parse the log id, convert hex into integer
            self.logID = int(tList[5], 16)
            # print hex(self.logID)
        else:
            self.title = None

    def __procDetail(self):
        if self.detail[0].find("not supported") != -1:
            self.detail = None
        else:
            # print "Process detail"
            if self.logID == const.RRC_ID:
                rrclist = self.detail[0].split()
                # extract int from parentheses
                self.rrcID = (int)(re.findall("\d+",rrclist[-1])[0])
                # print "Id:%s, RRC_state:%s" % (self.rrcID, const.RRC_MAP[self.rrcID])
            # TODO: process other type of log entry

    def __procHexDump(self):
        # print "Parse Hex Dump" 
        tempHex = {}
        tempHex["length"] = int((self.hex_dump[0].split())[1])
        tempHex["header"] = self.hex_dump[1].split()[1:]
        tempHex["payload"] = self.hex_dump[2].split()[1:]
        for i in self.hex_dump[3:]:
            tempHex["payload"] += i.split()
        self.hex_dump = tempHex
        # print self.hex_dump
    
    def __extractProtocolInfo(self):
        # print "Parse protocol type"
        # Structure:
        # Pyaload = Its own header + IP header
        if self.logID == const.PROTOCOL_ID:
            # Extract segmentation information
            # Extract transport layer information
            # length must greater than wrapping header plus IP header
            if len(self.hex_dump["payload"]) > Payload_Header_Len + 20 and \
               int(self.hex_dump["payload"][1], 16) == const.IP_ID:
                self.ip["seg_num"] = int(self.hex_dump["payload"][6], 16)
                if self.hex_dump["payload"][7][0] == '0':
                    self.ip["final_seg"] = False
                else:
                    self.ip["final_seg"] = True
                
                # IP packet parsing
                self.ip["header_len"] = int(self.hex_dump["payload"][Payload_Header_Len][1], 16) * 4
                if self.ip["header_len"] == IP_Header_Len:
                    start = Payload_Header_Len
                    self.ip["tlp_id"] = int(self.hex_dump["payload"][17], 16)
                    self.ip["total_len"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                    self.ip["src_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+12:start+16]])
                    self.ip["dst_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+16:start+20]])
                    # self.__debugIP()
                    
                    # Parse TCP Packet 
                    if self.ip["tlp_id"] == const.TCP_ID:
                        start = Payload_Header_Len + self.ip["header_len"]
                        self.tcp["src_port"] = int("".join(self.hex_dump["payload"][start:start+2]), 16)
                        self.tcp["dst_port"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                        flag = int(self.hex_dump["payload"][start+13], 16)
                        self.tcp["CWR"] = bool((flag >> 7) & 0x1)
                        self.tcp["ECE"] = bool((flag >> 6) & 0x1)
                        self.tcp["URG"] = bool((flag >> 5) & 0x1)
                        self.tcp["ACK"] = bool((flag >> 4) & 0x1)
                        self.tcp["PSH"] = bool((flag >> 3) & 0x1)
                        self.tcp["RST"] = bool((flag >> 2) & 0x1)
                        self.tcp["SYN"] = bool((flag >> 1) & 0x1)
                        self.tcp["FIN"] = bool(flag & 0x1)
                        # self.__debugTCP()
                    
                    # Parse UDP Packet
                    if self.ip["tlp_id"] == const.UDP_ID:
                        start = Payload_Header_Len + self.ip["header_len"] 
                        self.udp["src_port"] = int("".join(self.hex_dump["payload"][start:start+2]), 16)
                        self.udp["dst_port"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                        self.udp["total_len"] = int("".join(self.hex_dump["payload"][start+4:start+6]), 16)
                        # self.__debugUDP()
                        
                """
                print "segment number is %d" % (self.ip["seg_num"])
                print "Final segement is %d" % (self.ip["final_seg"])
                print self.ip["tlp_id"]
                """
                
    def __debugIP(self):
        print "ip header is %d" % (self.ip["header_len"])
        print "Protocol type is %d" % (self.ip["tlp_id"])
        print "src ip %s" % (self.ip["src_ip"])
        print "dst ip %s" % (self.ip["dst_ip"])
        
    def __debugTCP(self):
        print "TCP src port is %d" % (self.tcp["src_port"])
        print "TCP dst prot is %d" % (self.tcp["dst_port"])
        print "CWR is %d" % (self.tcp["CWR"])
        print "ECE is %d" % (self.tcp["ECE"])
        print "URG is %d" % (self.tcp["URG"])
        print "ACK is %d" % (self.tcp["ACK"])
        print "PSH is %d" % (self.tcp["PSH"])
        print "RST is %d" % (self.tcp["RST"])
        print "SYN is %d" % (self.tcp["SYN"])
        print "FIN is %d" % (self.tcp["FIN"])
        
    def __debugUDP(self):
        print "UDP src port is %d" % (self.udp["src_port"])
        print "UDP dst prot is %d" % (self.udp["dst_port"])
        print "UDP total length is %d" % (self.udp["total_len"])
                
