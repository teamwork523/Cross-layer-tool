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
import PrintWrapper as pw
from datetime import datetime

###############################################################################################
########################################### I/O Related #######################################
###############################################################################################
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
        if re.match("^[0-9]{4}", line.strip().split()[0]):
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

###############################################################################################
##################################### Mapping Functions #######################################
###############################################################################################

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

# assign the ip five tuple
def assignFlowInfo (entries):
    # ACT as a reference to the object -> Able to update directly afterwards
    privTuple = {}
    for entry in entries:
        if entry.logID == const.PROTOCOL_ID:
            if privTuple and not entry.flow:
                # Find the ACK number right and update the 
                if entry.tcp["seq_num"] == privTuple["seq_num"] + 1 and \
                   privTuple["ack_num"] == 0 and \
                   entry.tcp["ACK_FLAG"]:
                    privTuple["ack_num"] = entry.tcp["ack_num"]
                    privTuple["timestamp"] = entry.timestamp
                entry.flow = privTuple
            elif entry.flow:
                privTuple = entry.flow

# extract the data entry based on flow info
# @Return [[flow1_of_entries], [flow2_of_entries], ...]
def extractFlows (entries):
	flows = []
	localFlow = []
	for entry in entries:
		if entry.logID == const.PROTOCOL_ID and entry.ip["tlp_id"] == const.TCP_ID:
			if not entry.flow:
				localFlow.append(entry)
			elif localFlow:
				# start a new flow here
				flows.append(localFlow)
				localFlow = [entry]
	return flows		

# Use reselection for signal strength
def assignSignalStrengthValue(entries):
    mostRecentECIO = None
    mostRecentRSCP = None
    for entry in entries:
        if entry.logID == const.SIG_ID:
            if entry.sig["ECIO"]:
                mostRecentECIO = entry.sig["ECIO"]
            else:
                if mostRecentECIO:
                    entry.rssi["ECIO"] = mostRecentECIO
            if entry.sig["RSCP"]:
                mostRecentRSCP = entry.sig["RSCP"]
            else:
                if mostRecentRSCP:
                    entry.sig["RSCP"] = mostRecentRSCP
        else:  
            if mostRecentECIO:
                entry.sig["ECIO"] = mostRecentECIO
            if mostRecentRSCP:
                entry.sig["RSCP"] = mostRecentRSCP
    
# Use timestamp as key to create the map
def createTSbasedMap(entries):
    entryMap = {}
    for entry in entries:
        key = entry.timestamp * 1000
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
    	if cond.has_key("ip_relation") and cond["ip_relation"] == "and":
		    if i.logID == const.PROTOCOL_ID:
		        # ip src
		        if cond.has_key("src_ip") and i.ip["src_ip"] != cond["src_ip"]:
		           #(i.flow and i.flow["src_ip"] != cond["src_ip"])):
		            continue
		        # ip dst
		        if cond.has_key("dst_ip") and i.ip["dst_ip"] != cond["dst_ip"]:
		           #(i.flow and i.flow["dst_ip"] != cond["dst_ip"])):
		            continue
		        # transport layer type
		        if cond.has_key("tlp_id") and i.ip["tlp_id"] != cond["tlp_id"]:
		           #(i.flow and i.flow["tlp_id"] != cond["tlp_id"])):
		            continue
		        # src/dst port
		        if cond.has_key("tlp_id"):
		            if cond["tlp_id"] == const.TCP_ID:
		                if cond.has_key("src_port") and cond["src_port"] != i.tcp["src_port"]:
		                   #(i.flow and i.flow["src_port"] != cond["src_port"])):
		                    continue
		                if cond.has_key("dst_port") and cond["dst_port"] != i.tcp["dst_port"]:
		                   #(i.flow and i.flow["dst_port"] != cond["dst_port"])):
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
		            diff = i.timestamp * 1000 - privTime
		        ts = datetime.fromtimestamp(i.timestamp).strftime('%Y-%m-%d %H:%M:%S')
		        if startTime == 0:
		            startTime = i.timestamp
		        # print "%s %d %s %s %dms" % (ts, i.ip["total_len"], const.IDtoTLP_MAP[i.ip["tlp_id"]], const.RRC_MAP[i.rrcID], diff)
		        """
		        if i.rrcID == 2:
		            tab = "\t2\t0\t0"
		        elif i.rrcID == 3:
		            tab = "\t0\t3\t0"
		        elif i.rrcID == 4:
		            tab = "\t0\t0\t4"
		        print "%f %s %d" % (i.timestamp- startTime, tab, i.rrcID)
		        """
		        privTime = i.timestamp * 1000
		    else:
		        selectedEntries.append(i)
        elif cond.has_key("ip_relation") and cond["ip_relation"] == "or":
			if i.logID == const.PROTOCOL_ID:
				if cond.has_key("srv_ip") and \
				   (i.ip["src_ip"] == cond["srv_ip"] or i.ip["dst_ip"] == cond["srv_ip"]):
					selectedEntries.append(i)
    return selectedEntries

# No longer useful
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
        ts = datetime.fromtimestamp(p[pktKey][0].timestamp).strftime('%Y-%m-%d %H:%M:%S')
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

###############################################################################################
##################################### Retransmission Related ##################################
###############################################################################################

# process link layer retransmission
# IMPORTANT ASSUMPTION:
# 1. SN starts from 0 to a NUM (fixed in UL, not fixed in DL)
# 2. SN always increase
#
# ALGORITHM:
# 1. Compare the identical PDU's position difference in the whole UL/DL chain
#    if their difference is less than previous UL's period, then ReTx detected
# 2. ASSUME the packet drop happens less than half of the period for UL
#    Due flexibility of downlink SN period, we hard set a minimum period for DL
#
# RETURN:
# Function will return two list of maps (UL an DL) that count the 
# retransmission time for each SN
# TODO: Fix the downlink part, currenly using heuristics
def procRLCReTx(entries):
    ULCounter = 0
    DLCounter = 0
    ULPrivIndex = 0  # track for the period of index
    DLPrivIndex = 0  # track for the period of index
    # Track on the time based entry value
    DLPrivZeroTS = None
    ULPrivSN = None
    DLPrivSN = None
    ULLastPeriod = -1
    DLLastPeriod = -1
    # map between UL/DL SN and its most recent index and timestamp
    # {sn: (index, ts, entry)}
    ULSNMap = {}
    DLSNMap = {}
    # list Retransmission count for each period
    # i.e. [{SN1: [SN1_ReTxCount, 1st_ReTx_ts, duration, [entry1, entry2...]], SN2: [SN2_ReTxCount, 1st_ReTx_ts, duration, [entry1, entry2...]], ...} #period1,..., {...} #periodN]
    ULReTxCountMapList = []
    DLReTxCountMapList = []
    ULReTxCountMapLocal = {}
    DLReTxCountMapLocal = {}
    
    for entry in entries:
        if entry.logID == const.UL_PDU_ID:
            for i in range(len(entry.ul_pdu[0]["sn"])):
                curSN_UL = entry.ul_pdu[0]["sn"][i]
                ts_ul = entry.timestamp
                #print "UL: %d" % (curSN_UL)
                # check if duplication exist
                if (curSN_UL in ULSNMap) and (ULLastPeriod == -1 or ULCounter - ULSNMap[curSN_UL][0] < ULLastPeriod/5):
                    # duplication detected
                    ts_ul_formatted = datetime.fromtimestamp(ts_ul).strftime('%Y-%m-%d %H:%M:%S.%f')
                    #print "UL: %s\t%d\t%d\t%d" % (ts_ul_formatted, curSN_UL, ULCounter - ULSNMap[curSN_UL][0], ULLastPeriod)
                    if curSN_UL not in entry.retx["ul"]:
                        entry.retx["ul"][curSN_UL] = [entry.ul_pdu[0]["size"][i]]
                    else:
                        entry.retx["ul"][curSN_UL].append(entry.ul_pdu[0]["size"][i])
                    # update retx count map
                    if curSN_UL not in ULReTxCountMapLocal:
                    	# [tx_count, timestamp, duration]
                        ULReTxCountMapLocal[curSN_UL] = [1, ts_ul, ts_ul - ULSNMap[curSN_UL][1], [ULSNMap[curSN_UL][2], entry]]
                    else:
                        ULReTxCountMapLocal[curSN_UL][0] += 1
                        ULReTxCountMapLocal[curSN_UL][2] = ts_ul - ULReTxCountMapLocal[curSN_UL][1]
                        ULReTxCountMapLocal[curSN_UL][3].append(entry)
                else:
                    if curSN_UL == 0 and ULPrivIndex > const.MIN_SN_PERIOD:
                        # update the period and retx count map
                        ULLastPeriod = ULPrivIndex
                        ULPrivIndex = 0
                        if ULReTxCountMapLocal:
                            ULReTxCountMapList.append(ULReTxCountMapLocal)
                            ULReTxCountMapLocal = {}
                        #print "UL: Update Period for previous period %d" % (ULLastPeriod)
                    # update the Map
                    ULSNMap[curSN_UL] = (ULCounter, ts_ul, entry)
                    # We exclude the duplication one
                    incr = 1
                    if ULPrivSN:
                        incr = curSN_UL - ULPrivSN
                    ULCounter += 1
                    ULPrivIndex += 1
        elif entry.logID == const.DL_PDU_ID:
            for i in range(len(entry.dl_pdu[0]["sn"])):
                ts_dl = entry.timestamp
                curSN_DL = entry.dl_pdu[0]["sn"][i]
                # print "DL: %d" % (curSN_DL)
                # always reset from 0 in DL, since period is non-deterministic
                # Method 1: Count relative difference
                if curSN_DL == 0 and DLPrivIndex > const.MIN_SN_PERIOD:
                    # update the period
                    DLLastPeriod = DLPrivIndex
                    DLPrivIndex = 0
                    if DLReTxCountMapLocal:
                        DLReTxCountMapList.append(DLReTxCountMapLocal)
                        DLReTxCountMapLocal = {}
                    #print "DL: Update Period for previous period %d" % (DLLastPeriod)
                # Method 2: time difference
                """
                if curSN_DL == 0:
                    if DLPrivZeroTS:
                        if ts_dl - DLPrivZeroTS > const.RETX_PERIOD_THRESHOLD:
                            # update the period
                            DLLastPeriod = DLPrivIndex
                            DLPrivIndex = 0
                            if DLReTxCountMapLocal:
                                DLReTxCountMapList.append(DLReTxCountMapLocal)
                                DLReTxCountMapLocal = {}
                            #print "DL: Update Period for previous period %d" % (DLLastPeriod)
                            DLPrivZeroTS = ts_dl
                    else:
                        DLPrivZeroTS = ts_dl
                """
                # check if duplication exist
                if (curSN_DL in DLSNMap) and (DLLastPeriod == -1 or DLCounter - DLSNMap[curSN_DL][0] < DLLastPeriod*2/3):
                    # duplication detected
                    ts_dl_formatted = datetime.fromtimestamp(ts_dl).strftime('%Y-%m-%d %H:%M:%S.%f')
                    #print "DL: %s\t%d\t%d\t%d" % (ts_dl_formatted, curSN_DL, DLCounter - DLSNMap[curSN_DL][0], DLLastPeriod)
                    if curSN_DL not in entry.retx["dl"]:
                        entry.retx["dl"][curSN_DL] = [entry.dl_pdu[0]["size"][i]]
                    else:
                        entry.retx["dl"][curSN_DL].append(entry.dl_pdu[0]["size"][i])
                    # update retx count map
                    if curSN_DL not in DLReTxCountMapLocal:
                    	# [tx_count, timestamp, duration]
                        DLReTxCountMapLocal[curSN_DL] = [1, ts_dl, ts_dl - DLSNMap[curSN_DL][1], [DLSNMap[curSN_DL][2], entry]]
                    else:
                        DLReTxCountMapLocal[curSN_DL][0] += 1
                        DLReTxCountMapLocal[curSN_DL][2] = ts_dl - DLReTxCountMapLocal[curSN_DL][1]
                        DLReTxCountMapLocal[curSN_DL][3].append(entry)
                else:
                    # update the Map
                    DLSNMap[curSN_DL] = (DLCounter, ts_dl, entry)
                    # We exclude the duplication one
                    DLCounter += 1
                    DLPrivIndex += 1
    
    # check local map reminds anything
    if ULReTxCountMapLocal:
        ULReTxCountMapList.append(ULReTxCountMapLocal)
    if DLReTxCountMapLocal:
        DLReTxCountMapList.append(DLReTxCountMapLocal)
    #print "DL ReTx length is %d" % (len(DLReTxCountMapList))
    return [retxCountMapTransform(ULReTxCountMapList), \
            retxCountMapTransform(DLReTxCountMapList)]                    
            
# Transform the ReTx Count map into Timestamp key base
# Old format: {sn: [count, ts, duration, entry]}
# New format: {ts: {sn1:(count1,duration1, [entry1, entry2,...]), sn2:(count2, duration2, [entry1, entry2, ...]), ...}
def retxCountMapTransform (retxCountMapList):
    tsMap = {}
    for retxCountMap in retxCountMapList:
        for k, v in retxCountMap.items():
            if v[1] in tsMap:
                tsMap[v[1]][k] = (v[0], v[2], v[3])
            else:
                tsMap[v[1]] = {k: (v[0], v[2], v[3])}
    return tsMap

# check if an entry is a fast retransmission packet
# TODO: debug ReTx
def detectFastReTx (entry, entryHist, is_up, srv_ip):
    ack_count = 0
    last_ack = None
    detectFastReTx = False
    
    # fast decline if sequence number is increasing
    if (is_up and entry.ip["dst_ip"] != srv_ip) or \
       (not is_up and entry.ip["src_ip"] != srv_ip) or \
       entry.tcp["seg_size"] <= 0:
    	return False
    	
    for i in entryHist[::-1]:
        # Make sure we are in the opposite direction when we haven't detect a fast retx
        if not detectFastReTx and \
           (entry.ip["src_ip"] != i.ip["dst_ip"] or \
           entry.ip["dst_ip"] != i.ip["src_ip"]):
            continue
        # when we have found the fast retransmission, return the nearest entry 
        # with smaller or equivalent seq_num
        elif detectFastReTx:
        	# TODO: debug
			print "Detect fast retransmission"
			print "Ongoing pkt:"
			pw.printTCPEntry(entry)
			print "Checking pkt:"
			pw.printTCPEntry(i)
			if entry.ip["src_ip"] == i.ip["src_ip"] and \
			   entry.ip["dst_ip"] == i.ip["dst_ip"] and \
			   entry.tcp["seq_num"] >= i.tcp["seq_num"]:
				return i
			else:
				continue
 
        # Track the most recent 3 ACKs
       	if ((is_up and i.ip["src_ip"] == srv_ip) or \
       	   (not is_up and i.ip["dst_ip"] == srv_ip)) and \
       	   i.tcp["seg_size"] == 0:
       	    # fast determination by detecting small ack number
		    if entry.tcp["seq_num"] != i.tcp["ack_num"]:
		       	return False
		    else:
		        if not ack_count:
		       		last_ack = i
		        ack_count += 1
		    # Wireshark: the current packet should happen within 20 ms of the last dup ACK
		    if last_ack:
			    if entry.timestamp - last_ack.timestamp > const.LAST_ACK_GAP:
				    return False
			    last_ack = None
        if ack_count >= const.FAST_RETX_COUNT:
		    detectFastReTx = True
	return False

# check if an entry is a retransmission
# @return False -- Fail to find a duplicate packet
#		  Entry -- the original packet
def detectReTx (entry, entryHist, is_up, srv_ip):
	if (is_up and entry.ip["dst_ip"] != srv_ip) or \
       (not is_up and entry.ip["src_ip"] != srv_ip) or \
       entry.tcp["seg_size"] <= 0:          
		return False
    	
	for i in entryHist[::-1]:
        # Exceptional case:
        # 1. The sender's last ACK in three way handshake has same header as first packets (check the packet size)
        # 2. TSL vs TCP exactly the same header, need to exam the TSL header (TODO)
        # 3. Duplicate ACK -> check payload and flow destination
        #    Special case DUP ACK of SYN-ACK -> (seg_size > 0)
        # 4. Duplicate FIN_ACK vs. ACK -> check flags
        # 5. Duplicate SYN -> Enable ACK
        #####
        # Make sure we are in the same direction
		if entry.ip["src_ip"] != i.ip["src_ip"] or \
		   entry.ip["dst_ip"] != i.ip["dst_ip"]:
			continue
        # fast decline if sequence number is increasing
		if entry.tcp["seq_num"] > i.tcp["seq_num"]:
			return False
		if i.tcp["seg_size"] > 0 and \
		   entry.tcp["seq_num"] == i.tcp["seq_num"]:
           # entry.tcp["flags"] == i.tcp["flags"]
           # entry.ip["total_len"] == i.ip["total_len"]:
           #and entry.tcp["payload"] == i.tcp["payload"]:
			privTS = i.timestamp
			ts = entry.timestamp
			return i
	return False

# basic idea is to find the first ACK that 
def findDataFlowStartIndex(flow):
	for i in range(len(flow)):
		if flow[i].tcp["ACK_FLAG"] and not flow[i].tcp["SYN_FLAG"] and \
		   flow[i].tcp["seg_size"] == 0 and flow[i].tcp["seq_num"] == flow[0].tcp["seq_num"] + 1:
		   	return i+1
	return 0

####
# @return: A map of retransmission TCP packet -- {orig_ts: [orig_entry, retx_entry]}
def procTCPReTx (flows, direction, srv_ip):
	is_up = True
	if direction.lower() != "up":
		is_up = False
	tcpReTxMap = {}
	tcpFastReTxMap = {}
	for flow in flows:
		startPosition = findDataFlowStartIndex(flow)
		data_pkts = flow[startPosition:]
		# keep a list of previous packets which doesn't include retx and fast retx packets
		priv_pkts = []
		for i in range(len(data_pkts)):
			# First check if it is a fast retransmission, then examine wether it is a retransmission
			orig_fast_retx_entry = detectFastReTx(data_pkts[i], priv_pkts, is_up, srv_ip)
			if orig_fast_retx_entry:
				if orig_fast_retx_entry.timestamp in tcpFastReTxMap:
					tcpFastReTxMap[orig_fast_retx_entry.timestamp].append((orig_fast_retx_entry, data_pkts[i]))
				else:
					tcpFastReTxMap[orig_fast_retx_entry.timestamp] = [(orig_fast_retx_entry, data_pkts[i])]
			else:
				orig_entry = detectReTx(data_pkts[i], priv_pkts, is_up, srv_ip)
				if orig_entry:
					if orig_entry.timestamp in tcpReTxMap:
						tcpReTxMap[orig_entry.timestamp].append((orig_entry, data_pkts[i]))
					else:
						tcpReTxMap[orig_entry.timestamp] = [(orig_entry, data_pkts[i])]
				else:
					priv_pkts.append(data_pkts[i])
			        
	return (tcpReTxMap, tcpFastReTxMap)

# Count the TCP retransmission
def countTCPReTx(tcpRetxMap):
	return sum([len(i) for i in tcpRetxMap.values()])

# Deprecate:
# check if an entry's header and body in the retransmission part
def checkEntryExistInList (entry, entryHist):            
    for i in entryHist[::-1]:
        # Exceptional case:
        # 1. The sender's last ACK in three way handshake has same header as first packets (check the packet size)
        # 2. TSL vs TCP exactly the same header, need to exam the TSL header (TODO)
        # 3. Duplicate ACK -> check payload and flow destination
        #    Special case DUP ACK of SYN-ACK -> (len > 64, TODO: make this better)
        # 4. Duplicate FIN_ACK vs. ACK -> check flags
        # 5. Duplicate SYN -> Enable ACK
        if entry.tcp["ACK_FLAG"] and \
           entry.ip["total_len"] > 64 and \
           entry.tcp["seq_num"] == i.tcp["seq_num"] and \
           entry.tcp["flags"] == i.tcp["flags"] and \
           entry.ip["total_len"] == i.ip["total_len"] and \
           entry.tcp["payload"] == i.tcp["payload"]:
            """
            privTS = i.timestamp[0] + float(i.timestamp[1])/1000.0
            ts = entry.timestamp[0] + float(entry.timestamp[1])/1000.0
            print "#" * 50
            print "Priv TS is %s" % (datetime.fromtimestamp(privTS).strftime('%H:%M:%S.%f'))
            print "Current TS is %s" % (datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f'))
            """
            return True
    return False

# assign transport layer retransmission
def procTPReTx_old (entries):
    if not entries:
        return
    privEntryHist = []
    threshold = 30
    for entry in entries:
        if entry.logID == const.PROTOCOL_ID and entry.ip["tlp_id"] == const.TCP_ID:            
            if checkEntryExistInList(entry, privEntryHist):
               entry.retx["tp"].append(entry.ip["total_len"])
            if len(privEntryHist) < threshold:
                privEntryHist.append(entry)
            else:
                privEntryHist.pop(0)
                privEntryHist.append(entry)

# count the TCP retransmission
def countTCPReTx_old (entries):
    if not entries:
        return
    count = 0
    for entry in entries:
        if entry.ip["tlp_id"] == const.TCP_ID:
            count += len(entry.retx["tp"])
    return count

# log the RLC retransmission over time
# @return a new retransmission
def mapRLCReTxOverTime (entries, interval):
	total_duration = entries[-1].timestamp - entries[0].timestamp
	cur_seg_start_time = entries[0].timestamp
	ul_map = {}
	dl_map = {}
	cur_ul_retx = 0
	cur_dl_retx = 0
	for entry in entries:
		if entry.rrcID and (i.logID == const.UL_PDU_ID or i.logID == const.DL_PDU_ID):
			if entry.timestamp >= cur_seg_start_time + interval:
				ul_map[cur_seg_start_time] = cur_ul_retx
				dl_map[cur_seg_start_time] = cur_dl_retx
				cur_seg_start_time += interval
				cur_ul_retx = 0
				cur_dl_retx = 0
			else:
				if i.logID == const.UL_PDU_ID:
					cur_ul_retx += sum([len(x) for x in i.retx["ul"].values()])
				if i.logID == const.DL_PDU_ID:
					cur_dl_retx += sum([len(x) for x in i.retx["dl"].values()])
	return (ul_map, dl_map)

# Count how many RLC uplink is lost

########################################################################################
##################################### Context Related ##################################
########################################################################################
def calThrouhgput(entries, direction):
    # TODO: use the sequence number to compute the throughput
    for i in entries:
        if i.logID == const.PROTOCOL_ID and i.ip["tlp_id"] == const.TCP_ID and \
           i.flow and i.tcp["ACK_FLAG"] and not i.tcp["SYN_FLAG"]:
            cur_ts = i.timestamp
            # RULES:
            # 1) Uplink
            #    SAME src_ip: use seq_num; NOT SAME use ack_num
            # 2) Downlink
            #    SAME src_ip: use ack_num; NOT SAME use seq_num
            byte = 0
            if direction.lower() == "up":
                if i.ip["src_ip"] == i.flow["src_ip"] and i.ip["dst_ip"] == i.flow["dst_ip"]:
                    byte = i.tcp["seq_num"] - i.flow["seq_num"]
                elif i.ip["src_ip"] == i.flow["dst_ip"] and i.ip["dst_ip"] == i.flow["src_ip"]:
                    byte = i.tcp["ack_num"] - i.flow["seq_num"]
            else:
                if i.ip["src_ip"] == i.flow["src_ip"] and i.ip["dst_ip"] == i.flow["dst_ip"]:
                    byte = i.tcp["ack_num"] - i.flow["ack_num"]
                elif i.ip["src_ip"] == i.flow["dst_ip"] and i.ip["dst_ip"] == i.flow["src_ip"]:
                    byte = i.tcp["seq_num"] - i.flow["ack_num"]                    
            i.throughput = computeThroughput(byte, cur_ts - i.flow["timestamp"])
            """
            print "#" * 40
            print convert_ts_in_human(cur_ts)
            print cur_ts
            print "^^^^^^^^^ Flow info:"
            print i.flow
            print "~~~~~~~TCP:"
            print i.tcp
            print "@@@@@@@ IP: "
            print i.ip
            print "Byte is %f" % (byte)
            print "Time diff is %f" % (cur_ts - i.flow["timestamp"])
            print "Throught is : %d" % (i.throughput) 
            """
            

#############################################################################
############################ helper functions ###############################
#############################################################################    
def meanValue(li):
    return sum(li)/len(li)

def medianValue(li):
    if not li:
        return None
    if len(li) % 2 == 0:
        return (li[len(li)/2-1] + li[len(li)/2])/2.0
    if len(li) % 2 != 0:
        return li[len(li)/2]

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

def validateIP (ip_address):
    valid = re.compile("^([0-9]{1,3}.){3}[0-9]{1,3}")
    return valid.match(ip_address)

def computeThroughput (payload, time):
    if time <= 0:
        return 0
    else:
        return float(payload)/time

# Remove duplicated IP packets generated from QXDM
def removeQXDMDupIP(entries):
    dupIndex = []
    privEntryIndex = None
    privSignature = None
    # filter all the potential deleted entries
    for i in range(len(entries)):
        if entries[i].logID == const.PROTOCOL_ID:
            if entries[i].ip["tlp_id"] == const.TCP_ID:
                # We need to times 2 here, since two hex is a byte
                # Also we only check the first half of the service data header
                # since the SNs are always different
                if privSignature != None and \
                   entries[i].ip["signature"][const.Payload_Header_Len*2:] == privSignature[const.Payload_Header_Len*2:] and \
                   entries[i].ip["signature"][:const.Payload_Header_Len] != privSignature[:const.Payload_Header_Len]:
                    """
                    t1 = convert_ts_in_human(entries[i].timestamp)
                    t2 = convert_ts_in_human(entries[privEntryIndex].timestamp)
                    """
                    # Delete the smaller one
                    if entries[privEntryIndex].hex_dump["length"] > entries[i].hex_dump["length"]:
                        dupIndex.append(i)
                    else:
                        dupIndex.append(privEntryIndex)
                    privEntryIndex = None
                    privSignature = None
                else:
                    privSignature = entries[i].ip["signature"]
                    privEntryIndex = i
    
    # Actuall elimination
    rtEntries = []
    for i in range(len(entries)):
        if i not in dupIndex:
            rtEntries.append(entries[i])
    return rtEntries    

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

# use binary search to find the nearest value in the given list
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
# Deprecated
"""
def sycTimeLine(entries, tsDict):
    rssi_errSQR_dict = {}
    for entry in entries:
        if entry.logID == const.AGC_ID and entry.agc["RxAGC"]:
            ts = entry.timestamp*1000
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
"""

def convert_ts_in_human(ts):
	return datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')
