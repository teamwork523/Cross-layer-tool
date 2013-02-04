#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
Then map the packets from PCAP with the RRC states in the log
"""

import sys, re
import calendar
import const
from datetime import datetime
from optparse import OptionParser

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
        # log id
        self.logID = None
        # RRC id
        self.rrcID = None
        # order matters
        self.__procTitle()
        self.__procDetail()
        #self.__procHexDump()

    def __procTitle(self):
        print "Process Titile"
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
            print self.timestamp
            # Parse the log id
            self.logID = tList[5]
            print self.logID
        else:
            self.title = None

    def __procDetail(self):
        if self.detail[0].find("not supported") != -1:
            self.detail = None
        else:
            print "Process detail"
            if self.logID == const.RRC_ID:
                rrclist = self.detail[0].split()
                # extract int from parentheses
                self.rrcID = (int)(re.findall("\d+",rrclist[-1])[0])
                print "Id:%s, RRC_state:%s" % (self.rrcID, const.RRC_MAP[self.rrcID])

    def __procHexDump(self):
        print "c"

def init_optParser():
    optParser = OptionParser(usage="./%prog [-l, --log] QCAT_LOG_PATH")
    optParser.add_option("-l", "--log", dest="inQCATLogFile", default="", \
                         help="QCAT log file path")
    optParser.add_option("-p", "--pcap", dest="inPCAPFile", default="", \
                         help="PCAP trace file path")
    return optParser


def readQCATLog(inQCATLogFile): 
    infile = open(inQCATLogFile, "r")

    countNewline = 0
    titleAndDetail = []
    hexDump = []
    # store all entries in a list
    QCATEntries = []

    while True:
        line = infile.readline()
        if not line: break
        if line[0] == "%":
            continue
        if line.strip() == "":
            countNewline += 1
            if countNewline > 1 and countNewline % 2 == 1:
                print "*"*40
                print countNewline
                print titleAndDetail
                print hexDump
                QCATEntries.append(QCATEntry(titleAndDetail[0], 
                                             titleAndDetail[1:], hexDump))
                titleAndDetail = []
                hexDump = []
        else:
            if countNewline % 2 == 1:
                # title and detail
                titleAndDetail.append(line.strip())
            else:
                # hexdump
                hexDump.append(line.strip())

    return QCATEntries

def main():
    # read lines from input file
    optParser = init_optParser()
    (options, args) = optParser.parse_args()

    if options.inQCATLogFile == "":
        optParser.error("-l, --log: Empty filename")

    QCATEntries = readQCATLog(options.inQCATLogFile)

if __name__ == "__main__":
    main()
