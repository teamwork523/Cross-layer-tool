#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
Then map the packets from PCAP with the RRC states in the log
"""

import sys
import const
import QCATEntry as qe
from optparse import OptionParser

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
                QCATEntries.append(qe.QCATEntry(titleAndDetail[0], 
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

def assignRRCState(entries):
    mostRecentRRCID = None
    for entry in entries:
        if entry.logID == const.RRC_ID:
            mostRecentRRCID = entry.rrcID
        elif entry.logID == const.PROTOCOL_ID:
            if entry.rrcID == None and mostRecentRRCID != None:
                entry.rrcID = mostRecentRRCID

def main():
    # read lines from input file
    optParser = init_optParser()
    (options, args) = optParser.parse_args()

    if options.inQCATLogFile == "":
        optParser.error("-l, --log: Empty filename")

    QCATEntries = readQCATLog(options.inQCATLogFile)
    print len(QCATEntries)
    assignRRCState(QCATEntries)
    for i in QCATEntries:
        if i.rrcID != None and i.ip["tlp_id"] != None:
            print "RRC: %d, Protocol: %d" % (i.rrcID, i.ip["tlp_id"])


if __name__ == "__main__":
    main()
