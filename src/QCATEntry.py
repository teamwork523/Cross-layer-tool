#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013

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

Aggregate all the QCAT log information into this class. Part of the fields requires
context mapping functions to fill in.
"""

import re, math, struct, sys
import calendar
from datetime import datetime
import const
import Util as util

DEBUG = False
CUR_DEBUG = False
DL_CTRL_PDU_DEBUG = False

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
        # Three fields: length, header, payload
        self.hex_dump = hex_dump
        # timestamp: unix_timestamp_secs.millisec
        self.timestamp = 0.0
        # log id in integer
        self.logID = None
        # RRC id
        self.rrcID = None 
        # ReTx size list: RLC uplink, RLC downlink, Transport layer
        # For RLC retransmission record {"SN":["PDU_size",...],...} info as the retransmission
        self.retx = {"ul":{}, "dl":{}, "tp":[]}
        # flow information, Five tuple start in SYN packet (src/dst)(ip/port) + protocol type
        # Also record the start sequence number and ACK number
        self.flow = {}
        # customized header info
        self.custom_header = {"final_seg": None, \
                              "seg_num": None, \
                              "seq_num": None}
        # ip information
        self.ip = {"tlp_id": None, # transport layer protocol \
                   "src_ip": None, \
                   "dst_ip": None, \
                   "header_len": None, \
                   "total_len": 0, \
                   # Wrap header + Raw IP header + TCP/UDP header as signature
                   "signature": None}
        # TCP information
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
                    "ack_num": None, \
                    "seq_num": None, \
                    "flags": None, \
                    "payload": None, \
                    "header_len": None,\
                    "seg_size": None,\
                    "flow": None}
        # UDP fields
        # include manually injected sequence number in the first four bytes in payload
        self.udp = {"src_port": None, \
                    "dst_port": None, \
                    "seg_size": None, \
                    "seq_num":  None, \
                    "gap": None}
        # HTTP fields
        # Assume always use TCP to transmit
        # Currently support:
        # 1. request type
        # 2. Host name
        # 3. Referer
        # 4. Timer (hijacked)
        self.http = {"type": None, \
                     "host": None, \
                     "referer": None, \
                     "timer": None
                    }
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
        # since sn could be duplicated, bad idea to use it as a key in header
        # Header has one to one correlation with sn
        # Notice: numPDU is not accurate, since it include for both ctrl and data message 
        # The header is in the form of [{"p": None, "he": None, "li": [], "e": None, "data":[], "len": None, "sn": None},...]
        self.ul_pdu = [{"chan": None,
                        "sn": [],
                        "numPDU": None,
                        "size": [], # bytes
                        "header":[]}]
        # The header is in the form of [{"p": None, "he": None, "li": [], "e": None, "data":[], "len": None, "sn": None},...]
        self.dl_pdu = [{"chan": None,
                        "sn": [],
                        "numPDU": None,
                        "size": [], # bytes
                        "header":[]}]
        # the ctrl PDU
        # NOTICE that both DL_CTRL_PDU_ID and DL_PDU_ID could contribute to CTRL PDU
        self.dl_ctrl = {"chan": None,
                        "ack": None,
                        "reset": None, # boolean
                        "reset_ack": None, # boolean
                        "list": [] # [(seq_num1, len1), (seq_num2, len2), ...], while the log got cut off, so not all SNs included
                       }
        # TODO: currently hard configure the channel ID should be 19
        # uplink RLC configuration setting
        self.ul_config = {"chan": None, 
                          "radio_bearer_id": None,
                          "tx_win_size": None,
                          "reset_timer": None,
                          "max_reset": None,
                          "max_tx": None,
                          "is_discard": None,
                          # polling related
                          "poll": {
                              "poll_proh_timer": None,  # prohibit timer
                              "poll_timer": None,   # this applies on individual poll PDU, unit: ms
                              "poll_periodic_timer": None, # periodic timer expires, unit: ms
                              "poll_pdu": None, # poll every xxx PDU
                              "poll_sdu": None, # poll every xxx SDU
                              "is_last_tx_pdu_poll": None,
                              "is_last_retx_pdu_poll": None,
                              "poll_win_size": None}
                           }
        # downlink RLC configuration settting
        self.dl_config = {"chan": None,
                          "radio_bearer_id": None,
                          "receive_win_size": None,
                          "is_pdu_order_preserved": None,
                          "min_time_btw_poll": None,
                          "is_report_missing_pdu": None}
        self.dl_RLC_ACK = True  # a boolean determine if last ACK exist in RLC DL AM
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
        ########################################################################
        ############################ Context information #######################
        ########################################################################
        # Record signal strength information
        # Multiple Cell are considered
        self.sig = {"num_cells": None,
                    "ECIO": [],
                    "RSCP": []}
        # Record WCDMA signal messages: 
        # 1. channel type
        # 2. message Detail
        # 2.1 message type
        # 2.2 cell_update_cause (speciallized for UL_CCCH message)
        # 2.3 rrc state indicator (convert to same RRC ID we used)
        self.sig_msg = {"ch_type": None,
                        "msg": {"type": None,
                                "cell_update_cause": None,
                                "rrc_indicator": None}
                        }
        # TCP Throughput information based on ACK calculation
        self.throughput = -1
        # TCP / RLC RTT based on ARQ mechanism
        # UDP RTT is calculated based on the sequence number that manually
        # assigned in the application
        self.rtt = {"tcp": None, "udp": None, "rlc": None}

        ########################################################################
        ############################# Event information ########################
        ########################################################################
        # PRACH messages 
        self.prach = {"aich_status": None, \
                      "num_preambles": None, \
                      "signature": None, \
                      "sub_channel_num": None ,\
                      "rf_tx_power": None}  # unit is dBm
        # order matters
        self.__procTitle()
        self.__procDetail()
        self.__procHexDump()
        # Extract IP/TCP info
        self.__parseProtocol()

    # return timestamp and log ID
    @staticmethod
    def parse_title_line(title):
        tList = title.split()
        # TODO: Support time difference
        # Parse the timestamp, only support UTC right now
        year = (int)(tList[0])
        month = (int)(const.MONTH_MAP[tList[1].lower()])
        day = (int)(tList[2])
        [secsList, millisec] = tList[3].split('.')
        [hour, minutes, sec] = secsList.split(':')
        dt = datetime(year, month, day, (int)(hour), (int)(minutes), (int)(sec))
        unixTime = calendar.timegm(dt.utctimetuple())
        timestamp = unixTime + float(millisec) / 1000.0
        # print self.timestamp
        # Parse the log id, convert hex into integer
        logID = int(tList[5], 16)
        return (timestamp, logID)

    def __procTitle(self):
        # print "Process Titile"
        if self.title != "":
            (self.timestamp, self.logID) = self.parse_title_line(self.title)
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
                #print "Id:%s, RRC_state:%s" % (self.rrcID, const.RRC_MAP[self.rrcID])
            # Parse Uplink state entry
            elif self.logID == const.EUL_STATS_ID:
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
                        # TODO: fix SN by avoid this decoupling
                        cur_seq = int(info[1].split(" ")[1], 16)
                        self.ul_pdu[0]["sn"].append(cur_seq)
                        self.extractRLCHeaderInfo(self.ul_pdu[0], info, cur_seq, True)
                        if DEBUG:
                            print self.ul_pdu[0]
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
                index = 0
                for i in self.detail:
                    if i.find("DATA PDU") != -1:
                        info = i.split("::")[1].strip().split(", ")
                        self.dl_pdu[0]["chan"] = int(info[0].split(":")[0])
                        cur_seq = int(info[1].split("=")[1], 16)
                        self.dl_pdu[0]["sn"].append(cur_seq)
                        self.extractRLCHeaderInfo(self.dl_pdu[0], info, cur_seq, False)
                    elif i[:8] == "PDU Size":
                        if self.dl_pdu[0]["size"] == None:
                            self.dl_pdu[0]["size"] = [int(i.split()[-1])/8]
                        else:
                            self.dl_pdu[0]["size"].append(int(i.split()[-1])/8)
                    elif i[:14] == "Number of PDUs":
                        self.dl_pdu[0]["numPDU"] = int(i.split()[-1])
                    # include Control PDU part
                    if i.find("CTL PDU") != -1:
                        info = i.split("::")[1].strip().split(", ")
                        self.dl_ctrl["chan"] = int(info[0])
                        if info[-1].split()[-1] == "RESET":
                            self.dl_ctrl["reset"] = True
                        elif info[-1].split()[-1] == "ACK":
                            self.dl_ctrl["reset_ack"] = True
                        elif info[-1].split()[-1] == "STATUS":
                            if index + 2 < len(self.detail):
                                status_line = self.detail[index+2]
                                if status_line.find("ACK") != -1:
                                    self.dl_ctrl["ack"] = int(status_line.split()[-1])
                                elif status_line.find("LIST") != -1:
                                    # TODO: add more sequence number if log enabled
                                    seq_num = int(status_line.split(", ")[-2])
                                    length = int(status_line.split(", ")[-1].split()[-1])
                                    self.dl_ctrl["list"].append((seq_num, length))
                    index += 1
                if self.dl_pdu[0].has_key("li") and len(self.dl_pdu[0]["li"]) > 1:
                    print >> sys.err, "%s, FOUND multiple LI in Downlink!!!" % (util.convert_ts_in_human(self.timestamp))
                #self.__debugDownlinkRLC()
            # Parse the Signal Strength state
            # Assume the number of cell we get is always in WCDMA
            elif self.logID == const.CELL_RESELECTION_ID:
                # check for number of cell reached
                if self.detail[2].find("Num cells searched") != -1:
                    self.sig["num_cells"] = int(self.detail[2].split()[4])
                else:
                    raise Exception("Fail to detect number of cells")
                for i in self.detail[3:]:
                    if i.find("ECIO") != -1:
                        try:
                            self.sig["ECIO"].append(float(i.split()[2]))
                        except ValueError:
                            self.sig["ECIO"] = []
                    # May encounter end of statement with pending string case
                    if i.find("RSCP") != -1:
                        try:
                            self.sig["RSCP"].append(float(i.split()[2]))
                        except ValueError:
                            self.sig["RSCP"] = []
            # process downlink DL control packets
            elif self.logID == const.DL_CTRL_PDU_ID:
                # check for number of entities
                if int(self.detail[0].split()[-1]) != 1:
                    raise Exception("More than one entities in UL AM PDU")
                lineOfinterest = self.detail
                for index in range(len(lineOfinterest)):
                    if lineOfinterest[index].find("DATA PDU") != -1:
                        info = lineOfinterest[index].split("::")[1].strip().split(", ")
                        self.dl_pdu[0]["chan"] = int(info[0].split(":")[1])
                        cur_seq = int(info[1].split(" ")[1], 16)
                        self.dl_pdu[0]["sn"].append(cur_seq)
                        # Exactly the same format as UL_PDU_ID
                        self.extractRLCHeaderInfo(self.dl_pdu[0], info, cur_seq, True)
                        if DL_CTRL_PDU_DEBUG:
                            print self.dl_pdu[0]
                    elif lineOfinterest[index][:8] == "PDU Size":
                        self.dl_pdu[0]["size"].append(int(lineOfinterest[index].split()[-1])/8)
                    elif lineOfinterest[index][:14] == "Number of PDUs":
                        self.dl_pdu[0]["numPDU"] = int(lineOfinterest[index].split()[-1])
                    if lineOfinterest[index].find("CONTROL PDU") != -1:
                        # Debug
                        """
                        print lineOfinterest
                        print "Index is %d" % index
                        print "length of lineOfinterest is %d" % len(lineOfinterest)
                        """
                        info = lineOfinterest[index].split("::")[1].strip().split(", ")
                        self.dl_ctrl["chan"] = int(info[0].split(":")[1])
                        ctrl_type = info[1].split(" ")[-1]
                        statusIndex = index + 1
                        if statusIndex < len(lineOfinterest) and ctrl_type == "STATUS":
                            if lineOfinterest[statusIndex].find("ACK") != -1:
                                leftIndex = lineOfinterest[statusIndex].find("(")
                                rightIndex = lineOfinterest[statusIndex].find(")")
                                self.dl_ctrl["ack"] = int(lineOfinterest[statusIndex][leftIndex+1:rightIndex])
                            if lineOfinterest[statusIndex].find("LIST") != -1:
                                # TODO: right now only one line is useful, but if log changes, add more (sn, len) pair
                                sn_line = lineOfinterest[statusIndex + 1]
                                cur_sn = int(sn_line.split(" ")[1], 16)
                                cur_len = int(sn_line.split(" ")[-1])
                                self.dl_ctrl["list"].append((cur_sn, cur_len))
                        elif ctrl_type == "RESET":
                            self.dl_ctrl["reset"] = True
                        elif ctrl_type == "ACK":
                            self.dl_ctrl["reset_ack"] = True
                        break
            # parse the UL AM log and extract the configuration
            elif self.logID == const.UL_CONFIG_PDU_ID:
                # We target on the entity with the number we are interested in
                index = 0
                for index in range(len(self.detail)):
                    if self.detail[index].find("Data Logical Channel ID") != 1:
                        if self.detail[index].split()[-1] == str(const.DATA_LOGIC_CHANNEL_ID):
                            break
                if index < len(self.detail) - 1:
                    self.ul_config["chan"] = const.DATA_LOGIC_CHANNEL_ID
                    # find the index inline
                    for line in self.detail[index:index+13]:
                        if line.find("Radio Bearer ID") != -1:
                            self.ul_config["radio_bearer_id"] = int(line[-1])
                        if line.find("Transmit Wind Size") != -1:
                            self.ul_config["tx_win_size"] = int(line[-1])
                        if line.find("TMR RST") != -1:
                            resetEntries = line.split(",")
                            self.ul_config["reset_timer"] = int(resetEntries[0].split()[-1])
                            self.ul_config["max_reset"] = int(resetEntries[-1].split()[-1])
                        if line.find("SDU Discard") != -1:
                            self.ul_config["is_discard"] = (line.split(", ")[0].split(": ")[-1] != "No Discard")
                        if line.find("MAX DAT") != -1:
                            self.ul_config["max_tx"] = int(line.split(", ")[1].split("= ")[-1])
                        if line.find("TMR Poll Proh") != -1:
                            self.ul_config["poll"]["poll_proh_timer"] = int(line.split(", ")[0].split(" ")[-2])
                            self.ul_config["poll"]["poll_timer"] = int(line.split(", ")[1].split(" ")[-2])
                        if line.find("Poll PU") != -1:
                            self.ul_config["poll"]["poll_pdu"] = int(line.split(", ")[0].split(" ")[-1])
                            self.ul_config["poll"]["poll_sdu"] = int(line.split(", ")[-1].split(" ")[-1])
                        if line.find("Last Tx Poll") != -1:
                            self.ul_config["poll"]["is_last_tx_pdu_poll"] = (line.split(", ")[0].split()[-1] == "On")
                            self.ul_config["poll"]["is_last_retx_pdu_poll"] = (line.split(", ")[-1].split()[-1] == "On")
                        if line.find("Poll Win") != -1:
                            self.ul_config["poll"]["poll_win_size"] = int(line.split(", ")[0].split()[-1])
                            self.ul_config["poll"]["poll_periodic_timer"] = int(line.split(", ")[1].split()[-2])
            # parse the DL AM log and extract the configuration
            elif self.logID == const.DL_CONFIG_PDU_ID:
                # We target on the entity with the number we are interested in
                index = 0
                for index in range(len(self.detail)):
                    if self.detail[index].find("Data Logical Channel ID") != 1:
                        if self.detail[index].split()[-1] == str(const.DATA_LOGIC_CHANNEL_ID):
                            break
                if index < len(self.detail) - 1:
                    self.dl_config["chan"] = const.DATA_LOGIC_CHANNEL_ID
                    # find the index inline
                    for line in self.detail[index:index+11]:
                        if line.find("Radio Bearer ID") != -1:
                            self.dl_config["radio_bearer_id"] = int(line[-1])
                        if line.find("Receive Wind Size") != -1:
                            self.dl_config["receive_win_size"] = int(line.split(",")[0].split()[-1])
                        if line.find("RLC Preserve order of higher layer PDUs") != -1:
                            self.dl_config["is_pdu_order_preserved"] = (line.split()[-1] == "TRUE")
                        if line.find("Min Time Between Status Reports") != -1:
                            self.dl_config["min_time_btw_poll"] = int(line.split()[-2])
                        if line.find("UE should send status report for missing PU") != -1:
                            self.dl_config["is_report_missing_pdu"] = (line.split()[-1] == "TRUE")
            # Parsing the WCDMA signaling messages
            elif self.logID == const.SIG_MSG_ID:
                # Find the channel in the first line
                self.sig_msg["ch_type"] = self.detail[0].split(", ")[0].split(" = ")[-1]
                # check whether the channel type is what we want
                if self.sig_msg["ch_type"] in const.CH_TYPE_OF_INTEREST:
                    for line in self.detail[1:]:
                        # hunting for the message type
                        splittedLine = line.split()
                        if splittedLine[0] == "message":
                            self.sig_msg["msg"]["type"] = splittedLine[1]
                            if self.sig_msg["msg"]["type"] not in const.MSG_TYPE_OF_INTEREST:
                                break
                        if self.sig_msg["msg"]["type"] and splittedLine[0] in const.MSG_OF_INTEREST:
                            # get rid of the comma
                            if splittedLine[1][-1] == ",":
                                splittedLine[1] = splittedLine[1][:-1]
                            if splittedLine[0] == "rrc-StateIndicator":
                                if const.RRC_REVERSE_MAP.has_key(splittedLine[1]):
                                    self.sig_msg["msg"]["rrc_indicator"] = const.RRC_REVERSE_MAP[splittedLine[1]]
                                    break
                            elif splittedLine[0] == "cellUpdateCause":
                                self.sig_msg["msg"]["cell_update_cause"] = splittedLine[1]
                                break
            # Parsing the event messages
            elif self.logID == const.EVENT_ID:
                for line in self.detail[1:]:
                    if "AICH Status" in line:
                        splittedLine = line.split()
                        self.prach["aich_status"] = self.convertPRACHKeywordToID(splittedLine[-1])
                        break
            # Parsing PRACH parameter message
            elif self.logID == const.PRACH_PARA_ID:
                for line in self.detail:
                    if "AICH Status" in line:
                        splittedLine = line.split()
                        self.prach["aich_status"] = self.convertPRACHKeywordToID(splittedLine[-1])
                    elif "Signature" in line:
                        splittedLine = line.split()
                        self.prach["signature"] = int(splittedLine[-1])
                    elif "Num Preambles" in line:
                        splittedLine = line.split()
                        self.prach["num_preambles"] = int(splittedLine[-1])
                    elif "Sub Channel Number" in line:
                        splittedLine = line.split()
                        self.prach["sub_channel_num"] = int(splittedLine[-1])
                    elif "RF Tx Power" in line:
                        splittedLine = line.split()
                        self.prach["rf_tx_power"] = int(splittedLine[-2])
            # LTE RRC OTA message
            elif self.logID == const.LTE_RRC_OTA_ID:
                for line in self.detail:
                    if "PDU Number = " in line:
                        splittedLine = line.split()
                        self.sig_msg["ch_type"] = splittedLine[3]
                    elif "message c1" in line:
                        splittedLine = line.split(" :")
                        self.sig_msg["msg"]["type"] = splittedLine[1][1:]
            # TODO: process other type of log entry

    def __procHexDump(self):
        # print "Parse Hex Dump" 
        tempHex = {}
        tempHex["length"] = int((self.hex_dump[0].split())[1])
        tempHex["header"] = self.hex_dump[1].split()[1:]
        try:
            tempHex["payload"] = self.hex_dump[2].split()[1:]
        except IndexError:
            print self.title
        for i in self.hex_dump[3:]:
            tempHex["payload"] += i.split()
        self.hex_dump = tempHex
        # print self.hex_dump
    
    def __parseProtocol(self):
        # print "Parse protocol type"
        # Structure:
        # Pyaload = Its own header + IP header
        if self.logID == const.PROTOCOL_ID:
            # Notice: customized header parsing, apply this to apply 0x11EB entries
            # Little Indian
            self.custom_header["seq_num"] = int("".join(self.hex_dump["payload"][5:3:-1]), 16)
            self.custom_header["seg_num"] = int(self.hex_dump["payload"][6], 16)
            if self.hex_dump["payload"][7][0] == '0':
                self.custom_header["final_seg"] = False
            else:
                self.custom_header["final_seg"] = True
            # Extract segmentation information
            # Extract transport layer information
            # length must greater than wrapping header plus IP header
            if len(self.hex_dump["payload"]) > const.Payload_Header_Len + 20 and \
               int(self.hex_dump["payload"][1], 16) == const.IP_ID:
                if CUR_DEBUG:
                    print "*" * 40
                    print " ".join(self.hex_dump["payload"][4:6])
                    self.__debugCustomHeader()
                # IP packet parsing
                self.ip["header_len"] = int(self.hex_dump["payload"][const.Payload_Header_Len][1], 16) * 4
                # Avoid fragmented logging packets
                if self.ip["header_len"] == const.IP_Header_Len:
                    start = const.Payload_Header_Len
                    self.ip["tlp_id"] = int(self.hex_dump["payload"][17], 16)
                    self.ip["total_len"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                    self.ip["src_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+12:start+16]])
                    self.ip["dst_ip"] = ".".join([str(int(x, 16)) for x in self.hex_dump["payload"][start+16:start+20]])
                    # self.__debugIP()
                    
                    # Parse TCP Packet 
                    if self.ip["tlp_id"] == const.TCP_ID:
                        start = const.Payload_Header_Len + self.ip["header_len"]
                        if len(self.hex_dump["payload"]) - start < 20:
                            return
                        self.tcp["src_port"] = int("".join(self.hex_dump["payload"][start:start+2]), 16)
                        self.tcp["dst_port"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                        self.tcp["seq_num"] = int("".join(self.hex_dump["payload"][start+4:start+8]), 16)
                        #seq_hex = "".join(self.hex_dump["payload"][start+4:start+8])
                        #self.tcp["seq_num"] = struct.unpack('!f', seq_hex.decode('hex'))[0]
                        self.tcp["ack_num"] = int("".join(self.hex_dump["payload"][start+8:start+12]), 16)
                        #ack_hex = "".join(self.hex_dump["payload"][start+8:start+12])
                        #self.tcp["ack_num"] = struct.unpack('!f', ack_hex.decode('hex'))[0]
                        flag = int(self.hex_dump["payload"][start+13], 16)
                        self.tcp["CWR_FLAG"] = bool((flag >> 7) & 0x1)
                        self.tcp["ECE_FLAG"] = bool((flag >> 6) & 0x1)
                        self.tcp["URG_FLAG"] = bool((flag >> 5) & 0x1)
                        self.tcp["ACK_FLAG"] = bool((flag >> 4) & 0x1)
                        self.tcp["PSH_FLAG"] = bool((flag >> 3) & 0x1)
                        self.tcp["RST_FLAG"] = bool((flag >> 2) & 0x1)
                        self.tcp["SYN_FLAG"] = bool((flag >> 1) & 0x1)
                        self.tcp["FIN_FLAG"] = bool(flag & 0x1)
                        self.tcp["flags"] = flag
                        self.tcp["header_len"] = ((int(self.hex_dump["payload"][start+12], 16)) >> 4) * 4
                        self.tcp["seg_size"] = self.ip["total_len"] - self.ip["header_len"] - self.tcp["header_len"]
                        self.tcp["payload"] = self.hex_dump["payload"][start+self.tcp["header_len"]:]
                        # Assign flow information if it is a SYN packet
                        if self.tcp["SYN_FLAG"] and not self.tcp["ACK_FLAG"]:
                            self.flow["src_port"] = self.tcp["src_port"]
                            self.flow["dst_port"] = self.tcp["dst_port"]
                            self.flow["tlp_id"] = self.ip["tlp_id"]
                            self.flow["src_ip"] = self.ip["src_ip"]
                            self.flow["dst_ip"] = self.ip["dst_ip"]
                            self.flow["seq_num"] = self.tcp["seq_num"]
                            self.flow["ack_num"] = self.tcp["ack_num"]
                            self.flow["timestamp"] = self.timestamp
                        # self.__debugTCP()
                        # Use Artificial, IP and transport layer header as signature
                        self.ip["signature"] = "".join(self.hex_dump["payload"][:start+self.ip["header_len"]+self.tcp["header_len"]])

                        # Parse TCP packet (assume it always use TCP for transmission)
                        if self.tcp["src_port"] == 80:
                            self.http["type"] = "DATA"
                            # self.__debugHTTP()
                        if self.tcp["dst_port"] == 80:
                            http_start = const.Payload_Header_Len + self.ip["header_len"] + self.tcp["header_len"]
                            if ("".join(self.hex_dump["payload"][http_start:http_start+3])).decode("hex") == "GET":
                                self.http["type"] = "GET"
                            else:
                                self.http["type"] = "DATA"
                            #self.__debugHTTP()
                    # Parse UDP Packet
                    if self.ip["tlp_id"] == const.UDP_ID:
                        start = const.Payload_Header_Len + self.ip["header_len"] 
                        self.udp["src_port"] = int("".join(self.hex_dump["payload"][start:start+2]), 16)
                        self.udp["dst_port"] = int("".join(self.hex_dump["payload"][start+2:start+4]), 16)
                        self.udp["seg_size"] = int("".join(self.hex_dump["payload"][start+4:start+6]), 16) - const.UDP_Header_Len
                        if self.udp["seg_size"] >= 4:
                            try:
                                self.udp["seq_num"]  = int("".join(self.hex_dump["payload"][start+8:start+12]), 16)
                            except ValueError:
                                self.udp["seq_num"] = None
                        if self.udp["seg_size"] >= 12:
                            # use the wait_count and the granularity to calculate the gap period
                            try:
                                wait_count = int("".join(self.hex_dump["payload"][start+12:start+16]), 16)
                                gran = int("".join(self.hex_dump["payload"][start+16:start+20]), 16)
                                if wait_count >= 0 and wait_count < const.UDP_WAIT_LIMIT and gran > 0 and gran < const.UDP_GRAN_LIMIT:
                                    self.udp["gap"] = float(wait_count * gran) / 1000.0
                            except ValueError:
                                self.udp["gap"] = None
                        #print self.udp["gap"]
                        #self.__debugUDP()
                        # Use IP and transport layer header as signature
                        self.ip["signature"] = "".join(self.hex_dump["payload"][:start+self.ip["header_len"]+const.UDP_Header_Len])
                        
################################################################################   
################################# Helper Functions #############################
################################################################################
    # extract RLC header inforamtion
    def extractRLCHeaderInfo(self, pdu_field, info, cur_seq, isUp):
        header = {}
        header_len = 2
        if isUp:
            delimiter = ": "
            cur_index = 2
        else:
            delimiter = " = "
            cur_index = 3
        # extrace required field in the header
        # 1. Polling bit (line indicator = 1, last seg = 2), 2. Header extension
        header["p"] = int(info[cur_index].split(delimiter)[1])
        cur_index += 1
        header["he"] = int(info[cur_index].split(delimiter)[1])
        header["data"] = []
        header["sn"] = cur_seq
        cur_index += 1
        if header["he"] == 1:
            # extract length indicator and extended bit
            # there might be multiple length indicator, store all of them
            header["li"] = [int(info[cur_index].split(delimiter)[1])]
            cur_index += 1
            header["e"] = int(info[cur_index].split(delimiter)[1])
            cur_index += 1
            info_len = len(info)
            # determine the LI header length
            li_len = 1
            if pdu_field["size"][-1] > const.RLC_LI_THRESHOLD:
                li_len = 2
            header_len += li_len
            while header["e"] == 1 and cur_index < info_len:
                header["li"].append(int(info[cur_index].split(delimiter)[1]))
                cur_index += 1
                header["e"] = int(info[cur_index].split(delimiter)[1])
                cur_index += 1
                header_len += li_len
        # append the rest of info as data
        for i in range(cur_index, len(info)):
            # strip off the first 
            header["data"].append(info[cur_index].split(delimiter)[1][2:])
            cur_index += 1

        if pdu_field["size"]:
            header["len"] = pdu_field["size"][-1] - header_len
        else:
            print >> sys.stderr, "Didn't find PDU size before calculate the payload length"
            sys.exit(1)
        pdu_field["header"].append(header)
    
    # match PRACH keyword to PRACH ID
    def convertPRACHKeywordToID(self, keyword):
        for key in const.PRACH_KEY_TO_ID_MAP.keys():
            if key in keyword.upper():
                return const.PRACH_KEY_TO_ID_MAP[key]
        return None

    def __debugCustomHeader(self):
        print "Sequence number is %d" % (self.custom_header["seq_num"])
        print "Segment number is %d" % (self.custom_header["seg_num"])
        print "Final segement flag is %d" % (self.custom_header["final_seg"])
    
    def __debugIP(self):
        print "ip header is %d" % (self.ip["header_len"])
        print "Protocol type is %d" % (self.ip["tlp_id"])
        print "src ip %s" % (self.ip["src_ip"])
        print "dst ip %s" % (self.ip["dst_ip"])
        print "Signature is %s" % (self.ip["signature"])
        
    def __debugTCP(self):
        print "TCP src port is %d" % (self.tcp["src_port"])
        print "TCP dst prot is %d" % (self.tcp["dst_port"])
        print "SEQ number: %d" % (self.tcp["seq_num"])
        print "ack_num: %d" % (self.tcp["ack_num"])
        print "CWR_FLAG is %d" % (self.tcp["CWR_FLAG"])
        print "ECE_FLAG is %d" % (self.tcp["ECE_FLAG"])
        print "URG_FLAG is %d" % (self.tcp["URG_FLAG"])
        print "ACK_FLAG is %d" % (self.tcp["ACK_FLAG"])
        print "PSH_FLAG is %d" % (self.tcp["PSH_FLAG"])
        print "RST_FLAG is %d" % (self.tcp["RST_FLAG"])
        print "SYN_FLAG is %d" % (self.tcp["SYN_FLAG"])
        print "FIN_FLAG is %d" % (self.tcp["FIN_FLAG"])
        print "TCP header length is %d" % (self.tcp["header_len"])
        
    def __debugUDP(self):
        print "UDP src port is %d" % (self.udp["src_port"])
        print "UDP dst prot is %d" % (self.udp["dst_port"])
        print "UDP total length is %d" % (self.udp["seg_size"])
        if self.udp["seq_num"]:
            print "UDP sequence number is %d" % (self.udp["seq_num"])
        if self.udp["gap"]:
            print "UDP gap value is %d" % (self.udp["gap"])
        
    def __debugHTTP(self):
        print "HTTP type is %s" % (self.http["type"])

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

    def __debugDownlinkRLC(self):
        pdu = self.dl_pdu[0]
        print "*" * 40
        print util.convert_ts_in_human(self.timestamp)
        print "PDU sizes: %s" % (str(pdu["size"]))
        print "PDU SN: %s" % (str(pdu["sn"]))
        print "Data PDU detail: "
        for i in range(len(pdu["header"])):
            print "%dth PDU: %s" % (i, str(pdu["header"][i]))
                
