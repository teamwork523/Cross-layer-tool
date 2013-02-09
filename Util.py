#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
It could optionally map the packets from PCAP with the RRC states in the log
"""

import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
from datetime import datetime

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
                entry = qe.QCATEntry(titleAndDetail[0], titleAndDetail[1:], hexDump)
                QCATEntries.append(entry)
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
    PCAPPackets = []
    while True:
        line = infile.readline()
        if not line: break
        curIndex += 1
        if line[0] == "*":
            curIndex = 0
            if timestamp != 0 and millisec != 0 and payload != []:
                packet = pp.PCAPPacket(timestamp, millisec, payload)
                PCAPPackets.append(packet)
        if curIndex == 1:
            [timestamp, millisec] = line.split()
        if curIndex == 2:
            payload = line
    return PCAPPackets

def assignRRCState(entries):
    mostRecentRRCID = None
    for entry in entries:
        if entry.logID == const.RRC_ID:
            mostRecentRRCID = entry.rrcID
        elif entry.logID == const.PROTOCOL_ID:
            if entry.rrcID == None and mostRecentRRCID != None:
                entry.rrcID = mostRecentRRCID

# Use timestamp as key to create the map
def createTSbasedMap(entries):
    entryMap = {}
    for entry in entries:
        key = entry.timestamp[0] * 1000 + entry.timestamp[1]
        if entryMap.has_key(key) == False:
            entryMap[key] = [entry]
        else:
            entryMap[key].append(entry)
    return entryMap

# filter out proper packets
def packetFilter(entries, cond):
    selectedEntries = []
    for i in entries:
        # ip src
        if cond.has_key("src_ip") and i.ip["src_ip"] != cond["src_ip"]:
            continue
        # ip dst
        if cond.has_key("dst_ip") and i.ip["dst_ip"] != cond["dst_ip"]:
            continue
        # transport layer type
        if cond.has_key("tlp_id")and i.ip["tlp_id"] != cond["tlp_id"]:
            continue
        # src/dst port
        if cond.has_key("tlp_id"):
            if cond["tlp_id"] == const.TCP_ID:
                if cond.has_key("src_port") and cond["src_port"] != i.tcp["src_port"]:
                    continue
                if cond.has_key("dst_port") and cond["dst_port"] != i.tcp["dst_port"]:
                    continue
            elif cond["tlp_id"] == const.UDP_ID:
                if cond.has_key("src_port") and cond["src_port"] != i.udp["src_port"]:
                    continue
                if cond.has_key("dst_port") and cond["dst_port"] != i.udp["dst_port"]:
                    continue
        selectedEntries.append(i)

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
        if q.has_key(pktKey-const.TS_DELTA) and q[pktKey-const.TS_DELTA][0].rrcID != None:
            QCATSlow += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT slow)- %s %s %s" % (total, ts, const.IDtoTLP_MAP[q[pktKey-const.TS_DELTA][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey-const.TS_DELTA][0].rrcID])
            countMap[q[pktKey-const.TS_DELTA][0].rrcID] += 1
            continue
        elif q.has_key(pktKey) and q[pktKey][0].rrcID != None:
            QCATSame += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT same): %s %s %s" % (total, ts, const.IDtoTLP_MAP[q[pktKey][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey][0].rrcID])
            countMap[q[pktKey][0].rrcID] += 1
            continue
        elif q.has_key(pktKey+const.TS_DELTA) and q[pktKey+const.TS_DELTA][0].rrcID != None:
            QCATFast += 1
            total = QCATSlow + QCATSame + QCATFast
            print "%d(QCAT fast)+ %s %s %s" % (total, ts, const.IDtoTLP_MAP[q[pktKey+const.TS_DELTA][0].ip["tlp_id"]], \
                                    const.RRC_MAP[q[pktKey+const.TS_DELTA][0].rrcID])
            countMap[q[pktKey+const.TS_DELTA][0].rrcID] += 1
            continue
    countMap["fast"] = QCATFast
    countMap["same"] = QCATSame
    countMap["slow"] = QCATSlow
    return countMap
    
def validateIP (ip_address):
    valid = re.compile("^([0-9]{1,3}.){3}[0-9]{1,3}")
    return valid.match(ip_address)
