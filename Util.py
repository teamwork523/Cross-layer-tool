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
    
    isHex = False
    while True:
        line = infile.readline()
        if not line: break
        if line[0] == "%" or line.strip() == "":
            continue
        """
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
        """
        if line.strip().split()[0] == "2013":
            isHex = False
            if titleAndDetail != [] and hexDump != []:
                entry = qe.QCATEntry(titleAndDetail[0], titleAndDetail[1:], hexDump)
                QCATEntries.append(entry)
                titleAndDetail = []
                hexDump = []
            titleAndDetail.append(line.strip())
        elif line.strip().split()[0] == "Length:":
            isHex = True
            hexDump.append(line.strip())
        else:
            if isHex:
                hexDump.append(line.strip())
            else:
                titleAndDetail.append(line.strip())
    
    if titleAndDetail != [] and hexDump != []:
        entry = qe.QCATEntry(titleAndDetail[0], titleAndDetail[1:], hexDump)
        QCATEntries.append(entry)    

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
        else:
            if entry.rrcID == None and mostRecentRRCID != None:
                entry.rrcID = mostRecentRRCID

def assignEULState(entries):
    mostRecentRC = None
    mostRecentED = None
    mostRecentSpeed = None
    # need bottom up approach
    entries.reverse()
    for entry in entries:
        if entry.logID == const.EUL_STATS_ID:
            if entry.eul["t2p_ec"] != -1:
                mostRecentRC = entry.eul["t2p_ec"]
            if entry.eul["t2p_ed"] != -1:
                mostRecentED = entry.eul["t2p_ed"]
            if entry.eul["raw_bit_rate"] != 0:
                mostRecentSpeed = entry.eul["raw_bit_rate"]
        else:
            if mostRecentRC != None:
                entry.eul["t2p_ec"] = mostRecentRC
            if mostRecentED != None:
                entry.eul["t2p_ed"] = mostRecentED
            if mostRecentSpeed != None:
                entry.eul["raw_bit_rate"] = mostRecentSpeed
    entries.reverse()

def assignRSSIValue(entries):
    mostRecentTxRSSI = None
    mostRecentRxRSSI = None
    for entry in entries:
        if entry.logID == const.AGC_ID:
            if entry.rssi["Tx"]:
                mostRecentTxRSSI = entry.rssi["Tx"]
            else:
                if mostRecentTxRSSI:
                    entry.rssi["Tx"] = mostRecentTxRSSI
            if entry.rssi["Rx"]:
                mostRecentRxRSSI = entry.rssi["Rx"]
            else:
                if mostRecentRxRSSI:
                    entry.rssi["Rx"] = mostRecentRxRSSI
        else:  
            if mostRecentTxRSSI != None:
                entry.rssi["Tx"] = mostRecentTxRSSI
            if mostRecentRxRSSI:
                entry.rssi["Rx"] = mostRecentRxRSSI
            

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
    privTime = 0
    startTime = 0
    for i in entries:
        if i.logID == const.PROTOCOL_ID:
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
            if privTime == 0:
                diff = 0
            else:
                diff = i.timestamp[0]*1000+i.timestamp[1] - privTime
            ts = datetime.fromtimestamp(i.timestamp[0]).strftime('%Y-%m-%d %H:%M:%S')
            if startTime == 0:
                startTime = i.timestamp[0] + float(i.timestamp[1])/1000.0
            # print "%s %d %s %s %dms" % (ts, i.ip["total_len"], const.IDtoTLP_MAP[i.ip["tlp_id"]], const.RRC_MAP[i.rrcID], diff)
            """
            if i.rrcID == 2:
                tab = "\t2\t0\t0"
            elif i.rrcID == 3:
                tab = "\t0\t3\t0"
            elif i.rrcID == 4:
                tab = "\t0\t0\t4"
            print "%f %s %d" % (i.timestamp[0] + float(i.timestamp[1])/1000.0 - startTime, tab, i.rrcID)
            """
            privTime = i.timestamp[0]*1000+i.timestamp[1]
        else:
            selectedEntries.append(i)
    return selectedEntries

# process link layer retransmission
def procRLCReTx(Entries):
    seqNumULSet = set()
    seqNumDLSet = set()
    for entry in Entries:
        if entry.logID == const.UL_PDU_ID:
            for i in entry.ul_pdu[0]["sn"]:
                if i in seqNumULSet:
                    entry.retx["ul"] += 1
                else:
                    seqNumULSet.add(i)
        elif entry.logID == const.DL_PDU_ID:
            for i in entry.dl_pdu[0]["sn"]:
                if i in seqNumDLSet:
                    entry.retx["dl"] += 1
                else:
                    seqNumDLSet.add(i)
                    
# assign transport layer retransmission
def procTPReTx (entries):
    if not entries:
        return
    priv_ACK = None
    priv_SEQ = None
    for entry in entries:
        if entry.ip["tlp_id"] == const.TCP_ID:
            if not priv_ACK and not priv_SEQ:
                priv_ACK = entry.tcp["ACK_NUM"]
                priv_SEQ = entry.tcp["SEQ_NUM"]
                continue
            else:
                if entry.tcp["ACK_NUM"] and entry.tcp["SEQ_NUM"] and \
                   entry.tcp["ACK_NUM"] == priv_ACK and \
                   entry.tcp["SEQ_NUM"] == priv_SEQ:
                    entry.retx["tp"] += 1
            priv_ACK = entry.tcp["ACK_NUM"]
            priv_SEQ = entry.tcp["SEQ_NUM"]

# count the transport layer retransmission
def countReTx (entries):
    if not entries:
        return
    count = 0
    for entry in entries:
        if entry.ip["tlp_id"] == const.TCP_ID:
            count += entry.retx["tp"]
    return count

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


#############################################################################
############################ helper functions ###############################
#############################################################################
def meanValue(li):
    return sum(li)/len(li)

def conv_dmb_to_rssi(sig):
    # Detail at http://m10.home.xs4all.nl/mac/downloads/3GPP-27007-630.pdf
    MAX = -51
    MIN = -113
    rssi = 31
    if sig < MIN:
	    rssi = 0
    else:
	    rssi = (sig - MIN)/2
    return rssi
    
#############################################################################
############################ debug functions ################################
#############################################################################
def readFromSig(filename):
    fp = open(filename, "r")
    tsDict = {}
    tzDiff = 5*3600*1000
    while True:
        line = fp.readline()
        if not line: break
        [ts, rssi] = line.strip().split("\t")
        tsDict[int(ts)-tzDiff] = int(rssi)
    fp.close()
    return tsDict

# use binary search to find the nearest value
def binarySearch (target, sortedList):
    if not sortedList:
        return None
    if len(sortedList) == 1:
        return sortedList[0]
    if len(sortedList) == 2:
        if target-sortedList[0] > sortedList[1] - target:
            return sortedList[1]
        else:
            return sortedList[0]
    mid = sortedList[len(sortedList)/2]
    if target == mid:
        return mid
    elif target > mid:
        return binarySearch(target, sortedList[len(sortedList)/2:])
    else:
        return binarySearch(target, sortedList[:len(sortedList)/2+1])   
        
# check if AGC and real rssi value matches
def sycTimeLine(entries, tsDict):
    rssi_errSQR_dict = {}
    for entry in entries:
        if entry.logID == const.AGC_ID and entry.agc["RxAGC"]:
            ts = entry.timestamp[0]*1000+entry.timestamp[1]
            print "TS in QCAT is %d" % (ts)
            mappedTS = binarySearch(ts, sorted(tsDict.keys()))
            print entry.agc["RxAGC"]
            print conv_dmb_to_rssi(meanValue(entry.agc["RxAGC"]))
            print mappedTS
            print tsDict[mappedTS]
            rssi_errSQR_dict[mappedTS] = pow(float(conv_dmb_to_rssi(meanValue(entry.agc["RxAGC"])))
                                           - float(tsDict[mappedTS]), 2)
            print rssi_errSQR_dict[mappedTS]
    return rssi_errSQR_dict

