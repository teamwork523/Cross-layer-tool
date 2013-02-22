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
                    
# assign retransmission of transport layer and return total amount
def procTPReTx (entries):
    if not entries:
        return
    count = 0
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
                    count += 1
            priv_ACK = entry.tcp["ACK_NUM"]
            priv_SEQ = entry.tcp["SEQ_NUM"]
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

def printResult (entries):
    ULBytes_total = 0.0
    DLBytes_total = 0.0
    ReTxUL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    ReTxDL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    rrc_state = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    Bytes_on_fly = 0.0
    retxul_bytes = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    retxdl_bytes =  {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    for i in entries:
        ts = i.timestamp[0] + float(i.timestamp[1])/1000.0
        """
        if i.eul["t2p_ec"] != None and i.eul["t2p_ed"] != None:
            print "%f\t%f\t%f" % (ts, i.eul["t2p_ec"], i.eul["t2p_ed"])
        if i.eul["raw_bit_rate"] != None:
            print "%f\t%f" % (ts, i.eul["raw_bit_rate"])
        """
        if i.rrcID != None:
            # print "%f\t%d\t%d\t%d" % (ts, i.rrcID, i.retx["ul"], i.retx["dl"])
            rrc_state[i.rrcID] += 1
            ReTxUL[i.rrcID] += i.retx["ul"]
            ReTxDL[i.rrcID] += i.retx["dl"]
            if i.logID == const.PROTOCOL_ID:
                Bytes_on_fly += i.ip["total_len"]
            if i.logID == const.UL_PDU_ID:
                ULBytes_total += i.ul_pdu[0]["numPDU"]*i.ul_pdu[0]["size"]
                if i.retx["ul"] != 0:
                    retxul_bytes[i.rrcID] += i.retx["ul"]*i.ul_pdu[0]["size"]
            if i.logID == const.DL_PDU_ID:
                DLBytes_total += i.dl_pdu[0]["size"]
                if i.retx["dl"] != 0:
                    retxdl_bytes[i.rrcID] += i.retx["dl"]*i.dl_pdu[0]["size"]
            
    # print "***************"
    totUL = float(ReTxUL[2]+ReTxUL[3]+ReTxUL[4])
    totDL = float(ReTxDL[2]+ReTxDL[3]+ReTxDL[4])
    totState = float(rrc_state[2]+rrc_state[3]+rrc_state[4])
    totULBytes = float(retxul_bytes[2]+retxul_bytes[3]+retxul_bytes[4])
    totDLBytes = float(retxdl_bytes[2]+retxdl_bytes[3]+retxdl_bytes[4])
    # print "%d\t%d\t%d\t%d\t%d\t%d" % (ReTxUL[const.FACH_ID], ReTxUL[const.DCH_ID], ReTxUL[const.PCH_ID], ReTxDL[const.FACH_ID], ReTxDL[const.DCH_ID], ReTxDL[const.PCH_ID])
    
    """
    print "Total UL retx: %f" % (totUL)
    print "Total DL retx: %f" % (totDL)
    print "Total RRC state: %f" % (totState)
    """
    print "Total bytes on fly: %f" % (Bytes_on_fly)
    print "Total Uplink bytes: %d" % (ULBytes_total)
    print "Total Downlink bytes: %d" % (DLBytes_total)
    """
    print "Total Uplink RT bytes: %f" % (totULBytes)
    print "Total Downlink RT bytes: %f" % (totDLBytes)
    if totUL != 0.0:
        print "UL -- FACH %f, DCH %f, PCH %f" % (ReTxUL[const.FACH_ID]/totUL, ReTxUL[const.DCH_ID]/totUL, ReTxUL[const.PCH_ID]/totUL)
    if totDL != 0.0:
        print "DL -- FACH %f, DCH %f, PCH %f" % (ReTxDL[const.FACH_ID]/totDL, ReTxDL[const.DCH_ID]/totDL, ReTxDL[const.PCH_ID]/totDL)
    if totState != 0.0:
        print "State dist -- FACH %f, DCH %f, PCH %f" % (rrc_state[const.FACH_ID]/totState, rrc_state[const.DCH_ID]/totState, rrc_state[const.PCH_ID]/totState)
    if Bytes_on_fly != 0:
        print "RT fraction : %f" % ((totULBytes+totDLBytes)/Bytes_on_fly)
    if totULBytes != 0.0:
        print "UL Retx bytes -- FACH %f, DCH %f, PCH %f" % (retxul_bytes[const.FACH_ID]/totULBytes, retxul_bytes[const.DCH_ID]/totULBytes, retxul_bytes[const.PCH_ID]/totULBytes)
    if totDLBytes != 0.0:
        print "DL Retx bytes -- FACH %f, DCH %f, PCH %f" % (retxdl_bytes[const.FACH_ID]/totDLBytes, retxdl_bytes[const.DCH_ID]/totDLBytes, retxdl_bytes[const.PCH_ID]/totDLBytes)
    """
      
