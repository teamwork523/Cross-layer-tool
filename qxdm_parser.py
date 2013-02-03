#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
Then map the packets from PCAP with the RRC states in the log
"""

import sys
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

    # TODO
    def procTitle(self):
        print "a"

    def procDetail(self):
        print "b"

    def procHexDump(self):
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
