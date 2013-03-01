#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
Define QCAT log entry class
"""

import re, math
import calendar
from datetime import datetime
import const
import Util as util

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
        # ReTx size list: RLC uplink, RLC downlink, Transport layer
        # For RLC retransmission record {"SN":["PDU_size",...],...} info as the retransmission
        self.retx = {"ul":{}, "dl":{}, "tp":[]}
        # ip information
        self.ip = {"tlp_id": None, \
                   "seg_num": None, \
                   "final_seg": None, \
                   "src_ip": None, \
                   "dst_ip": None, \
                   "header_len": None, \
                   "total_len": 0, \
                   # Wrap header + Raw IP header + TCP header as signature
                   "signature": None}
        # TCP information
        # TODO: add more tcp fields
        self.tcp = {"src_port": None, \
                    "dst_port": None, \
                    "CWR_FLAG": None, \
                    "ECE_FLAG": None, \
                    "URG_FLAG": None, \
                    "ACK_FLAG": None, \
                    "PSH_FLAG": None, \
                    "RST_FLAG": None, \
                    "SYN_FLAG": None, \
                    "FIN_FLAG": None, \
                    "ACK_NUM": None, \
                    "SEQ_NUM": None}
        self.udp = {"src_port": None, \
                    "dst_port": None, \
                    "total_len": None}
        # TODO: Link layer state info parse
        #       1. Retransmission rate
        #       2. Row bits
        #       3. scheduled bits
        #       4. power limited bits
        self.eul = {"sample_len": None,
                    "tti": None, # ms
                    "retx_rate": None, 
                    "raw_bit_rate": None, # kbps
                    "sched_bit_rate": None, # kbps
                    "power_bit_rate": None, # kbps
                    "SG_bit_rate": None, # kbps
                    "t2p_ec": None, # mW
                    "t2p_ed": None, # mW
                    "sched_buffer": None, # bytes
                    "non_sched_buffer": None}
        # RLC UL/DL PDU
        # TODO: currently assume only one entities
        self.ul_pdu = [{"chan": None,
                        "sn": [],
                        "numPDU": None,
                        "size": [] }] # bytes
        self.dl_pdu = [{"chan": None,
                        "sn": [],
                        "numPDU": None,
                        "size": [] }] # bytes
        # AGC info, record all the Tx/Rx power info
        # Deprecated
        self.agc = {"sample_num": None,
                    "start_cfn": None,
                    "RxAGC": [],
                    "TxAGC": []}
        # Either calculated from AGC or acquired from most recent value
        # Deprecated
        self.rssi = {"Rx": None,
                     "Tx": None}
        # Record signal strength information
        # Multiple Cell are considered
        self.sig = {"num_cells": None,
                    "ECIO": [],
                    "RSCP": []}
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
            # Parse RRC state entry
            if self.logID == const.RRC_ID:
                rrclist = self.detail[0].split()
                # extract int from parentheses
                self.rrcID = (int)(re.findall("\d+",rrclist[-1])[0])
                # print "Id:%s, RRC_state:%s" % (self.rrcID, const.RRC_MAP[self.rrcID])
            # Parse Uplink state entry
            elif self.logID == const.EUL_STATS_ID:
                """
                {"sample_len": None,
                    "tti": None, # ms
                    "retx_rate": None, 
                    "raw_bit_rate": None, # kbps
                    "sched_bit_rate": None, # kbps
                    "power_bit_rate": None, # kbps
                    "SG_bit_rate": None, # kbps
                    "hs_power": None, # mW
                    "sched_buffer": None, # bytes
                    "non_sched_buffer": None}
                """
                self.eul["sample_len"] = float(self.detail[0].split()[-1])
                self.eul["tti"] = float(re.findall(r"[\d.-]+", self.detail[1].split()[-1])[0])
                # self.eul["retx_rate"] = float(self.detail[9].split()[-1].split(":")[1])/self.eul["sample_len"]
                self.eul["raw_bit_rate"] = float(self.detail[14].split()[-1])/self.eul["tti"]
                self.eul["sched_bit_rate"] = float(self.detail[15].split()[-1])/self.eul["tti"]
                self.eul["power_bit_rate"] = float(self.detail[17].split()[-1])/self.eul["tti"]
                self.eul["SG_bit_rate"] = float(self.detail[18].split()[-1])/self.eul["tti"]
                ec_power = self.detail[23].split()[-2]
                if ec_power != "=":
                    self.eul["t2p_ec"] = math.pow(10, float(ec_power)/10.0)*1000
                else:
                    self.eul["t2p_ec"] = -1
                ed_power = self.detail[24].split()[-2]
                if ed_power != "=":
                    self.eul["t2p_ed"] = math.pow(10, float(ed_power)/10.0)*1000
                else:
                    self.eul["t2p_ed"] = -1
                self.eul["sched_buffer"] = float(self.detail[32].split()[-2])
                self.eul["non_sched_buffer"] = float(self.detail[33].split()[-2])
            # Parse Uplink PDU state
            # TODO: currently assume only one entities
            elif self.logID == const.UL_PDU_ID:
                # check for number of entities
                if int(self.detail[0].split()[-1]) != 1:
                    raise Exception("More than one entities in UL AM PDU")
                for i in self.detail:
                    if i.find("DATA PDU") != -1:
                        info = i.split("::")[1].strip().split(", ")
                        self.ul_pdu[0]["chan"] = int(info[0].split(":")[1])
                        self.ul_pdu[0]["sn"].append(int(info[1].split(" ")[1], 16))
                    elif i[:8] == "PDU Size":
                        self.ul_pdu[0]["size"].append(int(i.split()[-1])/8)
                    elif i[:14] == "Number of PDUs":
                        self.ul_pdu[0]["numPDU"] = int(i.split()[-1])
                # Expand the PDU 
                self.ul_pdu[0]["size"] *= self.ul_pdu[0]["numPDU"]
            # Parse Downlink PDU state
            # TODO: currently assume only one entities
            elif self.logID == const.DL_PDU_ID:
                # check for number of entities
                if int(self.detail[0].split()[-1]) != 1:
                    raise Exception("More than one entities in DL AM PDU")
                for i in self.detail:
                    if i.find("DATA PDU") != -1:
                        info = i.split("::")[1].strip().split(", ")
                        self.dl_pdu[0]["chan"] = int(info[0].split(":")[0])
                        self.dl_pdu[0]["sn"].append(int(info[1].split("=")[1], 16))
                    elif i[:8] == "PDU Size":
                        if self.dl_pdu[0]["size"] == None:
                            self.dl_pdu[0]["size"] = [int(i.split()[-1])/8]
                        else:
                            self.dl_pdu[0]["size"].append(int(i.split()[-1])/8)
                    elif i[:14] == "Number of PDUs":
                        self.dl_pdu[0]["numPDU"] = int(i.split()[-1])
            # Parse the Signal Strength state
            # Assume the number of cell we get is always in WCDMA
            elif self.logID == const.SIG_ID:
                # check for number of
                if self.detail[2].find("Num cells searched") != -1:
                    self.sig["num_cells"] = int(self.detail[2].split()[4])
                else:
                    raise Exception("Fail to detect number of cells")
                for i in self.detail[3:]:
                    if i.find("ECIO") != -1:
                        self.sig["ECIO"].append(float(i.split()[-1]))
                    if i.find("RSCP") != -1:
                        self.sig["RSCP"].append(float(i.split()[-1]))
                print self.sig["ECIO"]
                print self.sig["RSCP"]
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
            if len(self.hex_dump["payload"]) > const.Payload_Header_Len + 20 and \
               int(self.hex_dump["payload"][1], 16) == const.IP_ID:
                self.ip["seg_num"] = int(self.hex_dump["payload"][6], 16)
                if self.hex_dump["payload"][7][0] == '0':
                    self.ip["final_seg"] = False
                else:
                    self.ip["final_seg"] = True

                # IP packet parsing
                self.ip["header_len"] = int(self.hex_dump["payload"][const.Payload_Header_Len][1], 16) * 4
                if self.ip["header_len"] == const.IP_Header_Len:
                    start = const.Payload_Header_Len
                    self.ip["tlp_id"] = int(self.hex_dump["payload"][17], 16)
                    self.ip["total_len"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                    self.ip["src_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+12:start+16]])
                    self.ip["dst_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+16:start+20]])
                    self.ip["signature"] = "".join(self.hex_dump["payload"][:start+const.IP_Header_Len+const.TCP_Header_Len])
                    # self.__debugIP()
                    
                    # Parse TCP Packet 
                    if self.ip["tlp_id"] == const.TCP_ID:
                        start = const.Payload_Header_Len + self.ip["header_len"]
                        self.tcp["src_port"] = int("".join(self.hex_dump["payload"][start:start+2]), 16)
                        self.tcp["dst_port"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                        self.tcp["SEQ_NUM"] = int("".join(self.hex_dump["payload"][start+4:start+8]), 16)
                        self.tcp["ACK_NUM"] = int("".join(self.hex_dump["payload"][start+8:start+12]), 16)
                        flag = int(self.hex_dump["payload"][start+13], 16)
                        self.tcp["CWR_FLAG"] = bool((flag >> 7) & 0x1)
                        self.tcp["ECE_FLAG"] = bool((flag >> 6) & 0x1)
                        self.tcp["URG_FLAG"] = bool((flag >> 5) & 0x1)
                        self.tcp["ACK_FLAG"] = bool((flag >> 4) & 0x1)
                        self.tcp["PSH_FLAG"] = bool((flag >> 3) & 0x1)
                        self.tcp["RST_FLAG"] = bool((flag >> 2) & 0x1)
                        self.tcp["SYN_FLAG"] = bool((flag >> 1) & 0x1)
                        self.tcp["FIN_FLAG"] = bool(flag & 0x1)
                        # self.__debugTCP()
                    
                    # Parse UDP Packet
                    if self.ip["tlp_id"] == const.UDP_ID:
                        start = const.Payload_Header_Len + self.ip["header_len"] 
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
        print "Signature is %s" % (self.ip["signature"])
        
    def __debugTCP(self):
        print "TCP src port is %d" % (self.tcp["src_port"])
        print "TCP dst prot is %d" % (self.tcp["dst_port"])
        print "SEQ number: %d" % (self.tcp["SEQ_NUM"])
        print "ACK_NUM: %d" % (self.tcp["ACK_NUM"])
        print "CWR_FLAG is %d" % (self.tcp["CWR_FLAG"])
        print "ECE_FLAG is %d" % (self.tcp["ECE_FLAG"])
        print "URG_FLAG is %d" % (self.tcp["URG_FLAG"])
        print "ACK_FLAG is %d" % (self.tcp["ACK_FLAG"])
        print "PSH_FLAG is %d" % (self.tcp["PSH_FLAG"])
        print "RST_FLAG is %d" % (self.tcp["RST_FLAG"])
        print "SYN_FLAG is %d" % (self.tcp["SYN_FLAG"])
        print "FIN_FLAG is %d" % (self.tcp["FIN_FLAG"])
        
    def __debugUDP(self):
        print "UDP src port is %d" % (self.udp["src_port"])
        print "UDP dst prot is %d" % (self.udp["dst_port"])
        print "UDP total length is %d" % (self.udp["total_len"])
        
    def __debugEUL(self):
        print "*"* 40
        print "sample length %f" % self.eul["sample_len"] 
        print "tti is %f " % self.eul["tti"]
        print "retransmission rate is %f" % self.eul["retx_rate"]
        print "Raw bit rate is %f" % self.eul["raw_bit_rate"] 
        print "Scheduled bit rate is %f" % self.eul["sched_bit_rate"] 
        print "Power bit rate is %f" % self.eul["power_bit_rate"] 
        print "SG bit rate is %f" % self.eul["SG_bit_rate"]
        print "Power EC is %f" % self.eul["t2p_ec"]
        print "Power ED is %f" % self.eul["t2p_ed"]
        print "scheduled buffer is %f" % self.eul["sched_buffer"]
        print "non scheduled buffer is %f" % self.eul["non_sched_buffer"]
                
