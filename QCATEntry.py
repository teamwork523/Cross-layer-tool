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
        self.ip = {}
        self.ip["tlp_id"] = None
        self.ip["seg_num"] = None
        self.ip["final_seg"] = None
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
        if self.logID == const.PROTOCOL_ID:
            # Extract segmentation information
            # Extract transport layer information
            # length must greater than wrapping header plus IP header
            if len(self.hex_dump["payload"]) > 8 + 20 and \
               int(self.hex_dump["payload"][1], 16) == const.IP_ID:
                self.ip["seg_num"] = int(self.hex_dump["payload"][6], 16)
                if self.hex_dump["payload"][7][0] == '0':
                    self.ip["final_seg"] = False
                else:
                    self.ip["final_seg"] = True
                self.ip["tlp_id"] = int(self.hex_dump["payload"][17], 16)
                """
                print "segment number is %d" % (self.ip["seg_num"])
                print "Final segement is %d" % (self.ip["final_seg"])
                print self.ip["tlp_id"]
                """
