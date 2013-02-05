#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
Then map the packets from PCAP with the RRC states in the log
"""

import os, sys
import const
import QCATEntry as qe
import PCAPPacket as pp
from optparse import OptionParser
from datetime import datetime

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
    QCATEntries = {}

    while True:
        line = infile.readline()
        if not line: break
        if line[0] == "%":
            continue
        if line.strip() == "":
            countNewline += 1
            if countNewline > 1 and countNewline % 2 == 1:
                entry = qe.QCATEntry(titleAndDetail[0], titleAndDetail[1:], hexDump)
                key = entry.timestamp[0]*1000 + entry.timestamp[1]
                if QCATEntries.has_key(key) == False:
                    QCATEntries[key] = [entry]
                else:
                    QCATEntries[key].append(entry)
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

def readPCAPResultFile(pcapResultFile):
    infile = open(pcapResultFile, "r")
    
    # TODO: might switch to directly read form PCAP file
    curIndex = 0
    timestamp = 0
    millisec = 0
    payload = 0
    PCAPPackets = {}
    while True:
        line = infile.readline()
        if not line: break
        curIndex += 1
        if line[0] == "*":
            curIndex = 0
            if timestamp != 0 and millisec != 0 and payload != []:
                packet = pp.PCAPPacket(timestamp, millisec, payload)
                key = packet.timestamp[0] * 1000 + packet.timestamp[1]
                if PCAPPackets.has_key(key) == False:
                    PCAPPackets[key] = [packet]
                else:
                    PCAPPackets[key].append(packet)
        if curIndex == 1:
            [timestamp, millisec] = line.split()
        if curIndex == 2:
            payload = line
    return PCAPPackets

def assignRRCState(entries):
    mostRecentRRCID = None
    for entryList in entries.values():
        for entry in entryList:
            if entry.logID == const.RRC_ID:
                mostRecentRRCID = entry.rrcID
            elif entry.logID == const.PROTOCOL_ID:
                if entry.rrcID == None and mostRecentRRCID != None:
                    entry.rrcID = mostRecentRRCID

def mapPCAPwithQCAT(p, q):
    countMap = {}
    QCATFast = 0
    QCATSame = 0
    QCATSlow = 0
    countMap[const.FACH_ID] = 0
    countMap[const.DCH_ID] = 0
    countMap[const.PCH_ID] = 0
    total = 0
    for pktKey in sorted(p.keys()):
        ts = datetime.fromtimestamp(p[pktKey][0].timestamp[0]).strftime('%Y-%m-%d %H:%M:%S')
        # Only map the first entry in the mapped list for right now
        if q.has_key(pktKey-const.TS_DELTA):
            QCATSlow += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT slow)- %s %s %s" % (total, ts, const.TLP_MAP[q[pktKey-const.TS_DELTA][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey-const.TS_DELTA][0].rrcID])
            countMap[q[pktKey-const.TS_DELTA][0].rrcID] += 1
            continue
        elif q.has_key(pktKey):
            QCATSame += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT same): %s %s %s" % (total, ts, const.TLP_MAP[q[pktKey][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey][0].rrcID])
            countMap[q[pktKey][0].rrcID] += 1
            continue
        elif q.has_key(pktKey+const.TS_DELTA):
            QCATFast += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT fast)+ %s %s %s" % (total, ts, const.TLP_MAP[q[pktKey+const.TS_DELTA][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey+const.TS_DELTA][0].rrcID])
            countMap[q[pktKey+const.TS_DELTA][0].rrcID] += 1
            continue
    countMap["fast"] = QCATFast
    countMap["same"] = QCATSame
    countMap["slow"] = QCATSlow
    return countMap

def main():
    # read lines from input file
    optParser = init_optParser()
    (options, args) = optParser.parse_args()

    if options.inQCATLogFile == "":
        optParser.error("-l, --log: Empty QCAT log filepath")
    if options.inPCAPFile == "":
        optParser.error("-p, --pcap: Empty PCAP filepath")

    QCATEntries = readQCATLog(options.inQCATLogFile)
    print len(QCATEntries)
    
    assignRRCState(QCATEntries)
    
    """
    for i in QCATEntries:
        if i.rrcID != None and i.ip["tlp_id"] != None:
            print "RRC: %d, Protocol: %d" % (i.rrcID, i.ip["tlp_id"])
    """
    # TODO: might consider not to use external traces
    outFile = "pcapResult.txt"
    os.system("pcap/main " + options.inPCAPFile + " > " + outFile)

    PCAPPackets = readPCAPResultFile(outFile)

    countMap = mapPCAPwithQCAT(PCAPPackets, QCATEntries)
    totalCount = countMap["fast"] + countMap["slow"] + countMap["same"]
    print "*"*40
    print "In total %d packets"%(len(PCAPPackets))
    print "Mapping rate is %f"%((float)(totalCount)/(float)(len(PCAPPackets)))
    print "QCAT ahead rate is %f"%((float)(countMap["fast"])/(float)(len(PCAPPackets)))
    print "QCAT same rate is %f"%((float)(countMap["same"])/(float)(len(PCAPPackets)))
    print "QCAT slow rate is %f"%((float)(countMap["slow"])/(float)(len(PCAPPackets)))
    print "DCH state rate is %f"%((float)(countMap[const.DCH_ID])/(float)(len(PCAPPackets)))
    print "FACH state rate is %f"%((float)(countMap[const.FACH_ID])/(float)(len(PCAPPackets)))
    print "PCH state rate is %f"%((float)(countMap[const.PCH_ID])/(float)(len(PCAPPackets)))

if __name__ == "__main__":
    main()
