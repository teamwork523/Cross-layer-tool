#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
It could optionally map the packets from PCAP with the RRC states in the log
"""

import os, sys, re, time, math
import hashlib, base64
import const
import QCATEntry as qe
import PCAPPacket as pp
import PrintWrapper as pw
from datetime import datetime

DEBUG = False
TIME_DEBUG = False
IP_DEBUG = True

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

# read PCAP file for timestamp verification
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
################## IP packet Invalide Elimination, Regroup and Validation #####################
###############################################################################################
# Eliminate the invalid IP packets
# Invalid Conditions:
# 1. Artificial Header implies a single packet, but IP length doesn't match the actual length
#
# Input: entry list with invalid IP log entries
# Ouput: entry list without invalid IP log entries
def eliminateInvalidIPPackets(rawEntryList):
    validEntryList = []
    
    for entry in rawEntryList:
        if entry.logID == const.PROTOCOL_ID:
            # Invalid Cond 1
            if entry.custom_header["final_seg"] == 1 and entry.custom_header["seg_num"] == 0:
                if len(entry.hex_dump["payload"]) - const.Payload_Header_Len != entry.ip["total_len"]:
                    continue
        validEntryList.append(entry)

    return validEntryList


# group segemanted IP packets together
# Append the segmented IP packets to the first one
#
# It is also possible that segements are not in consecutive sequence (though it is rare)
#
# Input: entry list with segmented IP log entries
# Ouput: 
# 1. entry list without segmented IP log entries
# 2. ungroupable entries
def groupSegmentedIPPackets(segEntryList):
    nonSegIPEntryList = []
    ungroupableEntryList = []
    ungroupableEntryBuffer = []
    IPEntryLead = None
    IPEntryLeadOrigPayloadLen = 0
    privSegNum = 0

    for entry in segEntryList:
        if entry.logID == const.PROTOCOL_ID:
            if entry.custom_header["final_seg"] == 1 and entry.custom_header["seg_num"] == 0:
                nonSegIPEntryList.append(entry)
                # eliminate pending ungroupable list
                if ungroupableEntryBuffer != []:
                    # reset first entry's payload
                    IPEntryLead.hex_dump["payload"] = IPEntryLead.hex_dump["payload"][:IPEntryLeadOrigPayloadLen]
                    ungroupableEntryList += ungroupableEntryBuffer
                    ungroupableEntryBuffer = []
            else:
                # check whether there will be consecutive IP packets in the future
                if entry.custom_header["seg_num"] == 0:
                    # first IP packet
                    IPEntryLead = entry
                    IPEntryLeadOrigPayloadLen = len(entry.hex_dump["payload"])
                    privSegNum = 0
                    ungroupableEntryBuffer.append(entry)
                elif IPEntryLead != None:
                    # detect whether the current segment number
                    ungroupableEntryBuffer.append(entry) 
                    if entry.custom_header["seg_num"] != privSegNum + 1:
                        # reset first entry's payload
                        IPEntryLead.hex_dump["payload"] = IPEntryLead.hex_dump["payload"][:IPEntryLeadOrigPayloadLen]
                        ungroupableEntryList += ungroupableEntryBuffer
                        ungroupableEntryBuffer = []
                        # reset the first entry as well
                        IPEntryLead = None
                        IPEntryLeadOrigPayloadLen = 0
                        continue
                    privSegNum = entry.custom_header["seg_num"]
                    # append the payload to the first IP packet
                    IPEntryLead.hex_dump["payload"] += entry.hex_dump["payload"][const.Payload_Header_Len:]
                    if entry.custom_header["final_seg"] == 1:
                        # reset the first IP packet as final segment
                        IPEntryLead.custom_header["final_seg"] = 1
                        # Last IP packet in a row
                        nonSegIPEntryList.append(IPEntryLead)
                        # reset the first of the group
                        IPEntryLead = None
                        IPEntryLeadOrigPayloadLen = 0
                        ungroupableEntryBuffer = []
                else:
                    # expect to start the segment number from 0
                    ungroupableEntryList.append(entry)
        else:
            nonSegIPEntryList.append(entry)

    return (nonSegIPEntryList, ungroupableEntryList)

# Recover the ungroupable Entry
#
# Possible resaons that entries are not groupable
# 1. Missing one or more logged entry
# 2. IP packets are not logged consecutively
#
# Recovery steps
# 1. Create a time to list of IP packet mapping 
# 2. try to regroup 
def recoveryUngroupPackets(ungroupableEntryList):
    timeToEntryListMap = {}
    recoveredEntryList = []

    for entry in ungroupableEntryList:
        if entry.timestamp in timeToEntryListMap:
            timeToEntryListMap[entry.timestamp].append(entry)
        else:
            timeToEntryListMap[entry.timestamp] = [entry]
    
    # try to regroup another time
    for ts in sorted(timeToEntryListMap.keys()):
        if IP_DEBUG:
            """
            print "#" * 80
            print "Ungrouped IP packet with the same timestamp\n"
            for entry in timeToEntryListMap[ts]:
                pw.printIPEntry(entry)
            """
        (regroupedEntryList, dummy) = groupSegmentedIPPackets(timeToEntryListMap[ts])
        if regroupedEntryList != []:
            recoveredEntryList += regroupedEntryList
            """
            if IP_DEBUG:
                print "^.^" * 20
                print "Success recoved IP packet\n"
                for entry in regroupedEntryList:
                    pw.printIPEntry(entry)
                    headerLen = entry.ip["header_len"]
                    if entry.ip["tlp_id"] == const.TCP_ID:
                        headerLen += entry.tcp["header_len"]
                    elif entry.ip["tlp_id"] == const.UDP_ID:
                        headerLen += const.UDP_Header_Len
                    print "".join(entry.hex_dump["payload"][const.Payload_Header_Len:const.Payload_Header_Len+headerLen])
            """

    return recoveredEntryList
            

# Insert back extra entry based on timestamp
# Use binary search to allocation the insertion place
# 
# Input: main entry list and valid ungrouped entry
# Output: inserted main entry list
def insertListOfEntries(mainEntryList, insertedEntryList):
    # create a timestamp list
    tsList = []

    for entry in mainEntryList:
        tsList.append(entry.timestamp)

    # Use binary search to insert
    for insertedEntry in insertedEntryList:
        insertIndex = binary_search_smallest_greater_index(insertedEntry.timestamp, 0, tsList)
        # remember to update timestamp list as well
        tsList.insert(insertIndex, insertedEntry.timestamp)
        mainEntryList.insert(insertIndex, insertedEntry)

    return mainEntryList


# Eliminate duplicate IP packets
# Conditions
# 1. Same TCP/IP header will be considered as duplication
#
# Input: entry list with duplicate IP log entries
# Ouput: entry list without duplicate IP log entries
# Limitation: only handle TCP and UDP packets now
def deDuplicateIPPackets(dupEntryList):
    nonDupEntryList = []
    headerSet = set()
    startIndex = const.Payload_Header_Len

    for entry in dupEntryList:
        if entry.logID == const.PROTOCOL_ID:
            if entry.ip["tlp_id"] == const.TCP_ID:
                header = "".join(entry.hex_dump["payload"][startIndex:startIndex+entry.ip["header_len"]+entry.tcp["header_len"]])
                if not header in headerSet:
                    nonDupEntryList.append(entry)
                    headerSet.add(header)
            elif entry.ip["tlp_id"] == const.UDP_ID:
                header = "".join(entry.hex_dump["payload"][startIndex:startIndex+entry.ip["header_len"]+const.UDP_Header_Len])
                if not header in headerSet:
                    nonDupEntryList.append(entry)
                    headerSet.add(header)
        else:
            nonDupEntryList.append(entry)

    return nonDupEntryList

# DEBUG function
# Detect which packet has been accidentally filtered out based on PCAP trace
# Input
# 1. list of entry from QxDM
# 2. list of entry from PCAP trace
def compareQxDMandPCAPtraces(qxdmEntryList, pcapIPList):
    qxdmIPMap = {}
    pcapIPMap = {}
    startIndex = const.Payload_Header_Len

    # generate Map for QxDM IP packets
    for entry in qxdmEntryList:
        if entry.logID == const.PROTOCOL_ID:
            if entry.ip["tlp_id"] == const.TCP_ID:
                header = "".join(entry.hex_dump["payload"][startIndex:startIndex+entry.ip["header_len"]+entry.tcp["header_len"]])
                if header not in qxdmIPMap:
                    qxdmIPMap[header] = entry
            elif entry.ip["tlp_id"] == const.UDP_ID:
                header = "".join(entry.hex_dump["payload"][startIndex:startIndex+entry.ip["header_len"]+const.UDP_Header_Len])
                if header not in qxdmIPMap:
                    qxdmIPMap[header] = entry
    
    # generate Map for pcap IP packets
    for ip in pcapIPList:
        if ip["tlp_raw_header"] != None and ip["ip_raw_header"] != None:
            header = ip["ip_raw_header"] + ip["tlp_raw_header"]
            if header not in pcapIPMap:
                pcapIPMap[header] = ip
    
    print "QxDM IP total is %d, PCAP IP total is %d" % (len(qxdmIPMap), len(pcapIPMap))
    
    qxdmNotInPcapCount = 0.0
    pcapNotInQxDMCount = 0.0

    # Check whether QxDM entry in the PCAP trace
    for qxdmIP in qxdmIPMap.keys():
        if qxdmIP not in pcapIPMap:
            qxdmNotInPcapCount += 1
            if IP_DEBUG:
                print "#" * 80
                print "!!! IMPOSSIBLE QxDM not appear in PCAP !!!"
                pw.printIPEntry(qxdmIPMap[qxdmIP])

    # Check whether PCAP IP packets appear in QxDM
    for pcapIP in pcapIPMap.keys():
        if pcapIP not in qxdmIPMap:
            pcapNotInQxDMCount += 1
            if IP_DEBUG:
                print "%" * 80
                print "~~~ PCAP IP not showed in QxDM, over filtered ~~~"
                print pcapIPMap[pcapIP]

    print 
    print "QxDM not in PCAP ratio %f / %f = %f" % (qxdmNotInPcapCount, len(qxdmIPMap), qxdmNotInPcapCount / len(qxdmIPMap))
    print "PCAP not in QxDM ratio %f / %f = %f" % (pcapNotInQxDMCount, len(pcapIPMap), pcapNotInQxDMCount / len(pcapIPMap))

# DEBUG function
# Validate whether the all the IP packets are non-duplicated
# Condition
# 1. IP length in the header should match the actual length
# 2. IP + TCP header should appear once
def validateIPPackets(entryList):
    packetToEntryMap = {}
    startIndex = const.Payload_Header_Len
    totalCount = 0.0
    invalidCount = 0.0

    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID:
            totalCount += 1
            if len(entry.hex_dump["payload"][startIndex:]) != entry.ip["total_len"]:
                invalidCount += 1
                print "#" * 80
                print "!!!! Invalid IP payload length !!!"
                pw.printIPEntry(entry)
                continue

            if entry.ip["tlp_id"] == const.TCP_ID:
                packet = "".join(entry.hex_dump["payload"][startIndex:])
                if packetToEntryMap.has_key(packet):
                    invalidCount += 1
                    print "#" * 80
                    print "### TCP packet existed ###"
                    print "Original TCP is:"
                    pw.printIPEntry(packetToEntryMap[packet])
                    print "Current TCP is:"
                    pw.printIPEntry(entry) 
                else:
                    packetToEntryMap[packet] = entry
            elif entry.ip["tlp_id"] == const.UDP_ID:
                packet = "".join(entry.hex_dump["payload"][startIndex:])
                if packetToEntryMap.has_key(packet):
                    invalidCount += 1
                    print "#" * 80
                    print "~~~ UDP packet existed ~~~~"
                    print "Original UDP is:"
                    pw.printIPEntry(packetToEntryMap[packet])
                    print "Current UDP is:"
                    pw.printIPEntry(entry) 
                else:
                    packetToEntryMap[packet] = entry

    print "="*80
    print "Total invalid ratio is %f / %f = %f" % (invalidCount, totalCount, invalidCount/totalCount)


###############################################################################################
########################################### Filtering #########################################
###############################################################################################
# WARNING: only support TCP right now
# Filter the packets to enable multiple IP analysis
# @ return (A, B)
# A: non-ip entry list
# B: map of ip entry list, with (k, v) as (srv_ip, ip_entries_list)
def multiIPFilter(entries, client_ip):
    nonIPEntries = []
    IPEntriesMap = {}

    for entry in entries:
        if entry.logID != const.PROTOCOL_ID:
            nonIPEntries.append(entry)
        elif entry.ip["tlp_id"] != const.UDP_ID:
            # eliminate all the UDP protocol, i.e. DNS lookup
            # client IP must appear as either in source or destination IP
            target_ip = ""
            if entry.ip["src_ip"] == client_ip:
                target_ip = entry.ip["dst_ip"]
            elif entry.ip["dst_ip"] == client_ip:
                target_ip = entry.ip["src_ip"]

            if target_ip != "":
                if target_ip in IPEntriesMap:
                    IPEntriesMap[target_ip].append(entry)
                else:
                    IPEntriesMap[target_ip] = [entry]

    return (nonIPEntries, IPEntriesMap)

# filter out proper packets
def packetFilter(entries, cond):
    selectedEntries = []
    privTime = 0
    startTime = 0
    
    # Filter decision flags
    NONIP_FLAG = (cond.has_key("keep_non_ip_entries") and cond["keep_non_ip_entries"])
    OR_FLAG = (cond.has_key("ip_relation") and cond["ip_relation"] == "or")
    AND_FLAG = (cond.has_key("ip_relation") and cond["ip_relation"] == "and")
    
    # Useful if we want to include all the fragmented IP packet into the trace
    Detect_Frag = False

    for i in entries:
        # append the non-ip entries if desired
        if NONIP_FLAG:
            if i.logID != const.PROTOCOL_ID:
                selectedEntries.append(i)
                continue
        # filter on IP entries
        # Case 1: filter for single direction
    	if AND_FLAG:
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
        # Case 2: filter for both direction
        elif OR_FLAG:
            if i.logID == const.PROTOCOL_ID:
                if not NONIP_FLAG:
				    if cond.has_key("srv_ip") and \
				       (i.ip["src_ip"] == cond["srv_ip"] or i.ip["dst_ip"] == cond["srv_ip"]):
					    selectedEntries.append(i)
                else:
                    # Include the following fragmented IP
                    if cond.has_key("srv_ip") and \
				       (i.ip["src_ip"] == cond["srv_ip"] or i.ip["dst_ip"] == cond["srv_ip"]):
                        selectedEntries.append(i)
                        if not i.custom_header["final_seg"]:
                            # find current segment is not final
                            Detect_Frag = True
                    elif cond.has_key("srv_ip"):
                        if Detect_Frag:
                            selectedEntries.append(i)
                            if i.custom_header["final_seg"]:
                                Detect_Frag = False
                                if DEBUG:
                                    print "Append fragment packet: %d" % (i.custom_header["seg_num"])
                                    pw.printEntry(i)

    return selectedEntries

# Not that useful
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
                
# Deprecated:
# record the RLC retransmission over time
# @return a sampling map, where each peirod 
def mapRLCReTxOverTime (entries, interval):
	total_duration = entries[-1].timestamp - entries[0].timestamp
	cur_seg_start_time = entries[0].timestamp
	ul_map = {}
	dl_map = {}
	cur_ul_retx = 0
	cur_dl_retx = 0
	for entry in entries:
		if entry.rrcID and (entry.logID == const.UL_PDU_ID or entry.logID == const.DL_PDU_ID):
			if entry.timestamp >= cur_seg_start_time + interval:
				ul_map[cur_seg_start_time] = (cur_ul_retx, entry.rrcID)
				dl_map[cur_seg_start_time] = (cur_dl_retx, entry.rrcID)
				cur_seg_start_time += interval
				cur_ul_retx = 0
				cur_dl_retx = 0
			else:
				if entry.logID == const.UL_PDU_ID:
					cur_ul_retx += sum([len(x) for x in entry.retx["ul"].values()])
				if entry.logID == const.DL_PDU_ID:
					cur_dl_retx += sum([len(x) for x in entry.retx["dl"].values()])
	return (ul_map, dl_map)        

#############################################################################
###################### Data Pre-process functions ###########################
############################################################################# 
# New!
# Find the client IP address based on the address count
def findClientIP(entries):
    ipAddrCount = {}
    
    # filter all the IP packets
    for i in range(len(entries)):
        cur_entry = entries[i]
        # count segmented IP packets as one
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.custom_header["seg_num"] == 0:
            src_ip = cur_entry.ip["src_ip"]
            dst_ip = cur_entry.ip["dst_ip"]
            if src_ip in ipAddrCount:
                ipAddrCount[src_ip] += 1
            else:
                ipAddrCount[src_ip] = 1
            if dst_ip in ipAddrCount:
                ipAddrCount[dst_ip] += 1
            else:
                ipAddrCount[dst_ip] = 1

    # sort the count map based on count by descending order
    sortedIpAddrCount = sorted(ipAddrCount.items(), key=lambda ipAddrCount: ipAddrCount[1], reverse=True)

    return sortedIpAddrCount[0][0]

# Remove duplicated IP packets generated from QXDM
def removeQXDMDupIP(entries):
    check_point_time = time.time()
    if TIME_DEBUG:
        print "Start delete dup IP"

    dupIndex = []
    privEntryIndex = None
    privSignature = None
    # filter all the potential deleted entries
    # TODO: modify this to allow a longer match
    for i in range(len(entries)):
        if entries[i].logID == const.PROTOCOL_ID:
            if entries[i].ip["tlp_id"] == const.TCP_ID or entries[i].ip["tlp_id"] == const.UDP_ID:
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
    
    if TIME_DEBUG:
        print "Delete entries takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()   
    
    # Actuall elimination
    rtEntries = []
    dupIndex = set(dupIndex)
    for i in range(len(entries)):
        if i not in dupIndex:
            rtEntries.append(entries[i])
    return rtEntries    

# Create a Map between entry and its index in the entry
# Assume no change on the entry later
def createEntryMap(entries):
    entryMap = {}
    for i in range(len(entries)):
        entryMap[entries[i]] = i
    return entryMap

#############################################################################
############################ helper functions ###############################
#############################################################################    
def meanValue(li):
	if not li:
		return 0.0
	return sum(li)*1.0/len(li)

def listMeanValue(li):
    if not li:
        return 0.0
    return meanValue([meanValue(item) for item in li])

# Get the statistical distribution info
# @return 
#   [5%, 25%, 50%, 75%, 95%]
def quartileResult(li):
    if not li:
        return [0]*5
    listLen = len(li)
    sorted_list = sorted(li)
    return [sorted_list[int(0.05*listLen)], sorted_list[int(0.25*listLen)], sorted_list[int(0.5*listLen)], \
            sorted_list[int(0.75*listLen)], sorted_list[int(0.95*listLen)]]

# calculate the standard deviation of the list
def stdevValue(li, mean = None):
    if not li:
        return 0.0

    if not mean:
        mean = meanValue(li)

    diff_sum = 0.0
    for i in li:
        diff_sum += (i-mean)*(i-mean)
    return math.sqrt(diff_sum / len(li))

# Get both mean and standard dev
def meanStdevPair(li, upper_bound = None):
    li = [i for i in li if i != 0.0 and (not upper_bound or (upper_bound and i < upper_bound))]
    mean = meanValue(li)
    return (mean, stdevValue(li, mean))

# convert list to string with delimiters
def listToStr(li, DEL = "\t"):
    return DEL.join(str(li)[1:-1].split(", "))

def medianValue(li):
    if not li:
        return None
    if len(li) % 2 == 0:
        return (li[int(len(li)*1.0/2)-1] + li[int(len(li)*1.0/2)])/2.0
    if len(li) % 2 != 0:
        return li[int(len(li)*1.0/2)]

def set_belongs_to(A, B):
    for i in A:
        if not i in B:
            return False
    return True

# over threshold% of A in B
def set_partial_belongs_to (A, B, threshold):
    real_th = int(float(len(A) * threshold) / 100.0)
    count = 0
    for i in A:
        if i in B:
            count += 1
        if count >= real_th:
            return True
    return False

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

## Used in verify PCAP timestamp that maps with QCAT log
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

# merge two dictionaries
# if two dicts have diff key sets, then return the original key set
# else return the merged one
def merge_two_dict(orig_dict, append_dict):
    if sorted(orig_dict.keys()) != sorted(append_dict.keys()):
        return orig_dict
    for key in orig_dict:
        orig_dict[key] += append_dict[key]
    return orig_dict

def convert_ts_in_human(ts, year=False, tz='utc'):
    dt = None
    if tz.lower() == 'utc':
        dt = datetime.utcfromtimestamp(ts)
    else:
        # use local PC timezone
        dt = datetime.fromtimestamp(ts)

    if year == False:
    	return dt.strftime("%H:%M:%S.%f")
    else:
        t = dt.strftime("%Y %b %d  %H:%M:%S.%f")
        # extra rounding work for Microsecond
        tail = t[-7:]
        f = round(float(tail), 3)
        return "%s%.3f" % (t[:-7], f)

# compute md5 hash
def md5_hash(data):
    # have to put it here to avoid inconsistent hash
    MD5 = hashlib.md5(data)
    return base64.b64encode(MD5.digest(), '._').strip('=')
    # return data

# determine the TCP flag string
# Sample output: "SYN" + DEL + "ACK"
def get_tcp_flag_info(entry, DEL):
    result = ""
    if entry.tcp["CWR_FLAG"]:
        result += "CWR" + DEL
    if entry.tcp["ECE_FLAG"]:
        result += "ECE" + DEL
    if entry.tcp["URG_FLAG"]:
        result += "URG" + DEL
    if entry.tcp["ACK_FLAG"]:
        result += "ACK" + DEL
    if entry.tcp["PSH_FLAG"]:
        result += "PSH" + DEL
    if entry.tcp["RST_FLAG"]:
        result += "RST" + DEL
    if entry.tcp["SYN_FLAG"]:
        result += "SYN" + DEL
    if entry.tcp["FIN_FLAG"]:
        result += "FIN" + DEL
    if len(result) > 0:
        return result[:-1]
    return result

# merge two entry lists based on timestamp
def merge_two_entry_lists(nonIP, IP):
    IP_cur_index = 0
    nonIP_cur_index = 0
    merged_entry = []    
    nonIP_len = len(nonIP)
    IP_len = len(IP)

    while True:
        if IP_cur_index >= IP_len or nonIP_cur_index >= nonIP_len:
            break
        if nonIP[nonIP_cur_index].timestamp < IP[IP_cur_index].timestamp:
            merged_entry.append(nonIP[nonIP_cur_index])
            nonIP_cur_index += 1
        else:
            merged_entry.append(IP[IP_cur_index])
            IP_cur_index += 1

    if IP_cur_index >= IP_len:
        merged_entry += nonIP[nonIP_cur_index:]
    if nonIP_cur_index >= nonIP_len:
        merged_entry += IP[IP_cur_index:]

    return merged_entry

# Get log of interest based on the network type and direction
def get_logID_of_interest(network_type, direction):
    # TODO: add LTE if necessary
    if network_type.lower() == "wcdma":
        if direction.lower() == "up":
            return const.UL_PDU_ID
        else:
            return const.DL_PDU_ID

# return the corresponding pdu entry based on id
def find_pdu_based_on_log_id(entry, log_id):
    # TODO: add LTE if necessary
    if log_id == const.UL_PDU_ID:
        return entry.ul_pdu[0]
    elif log_id == const.DL_PDU_ID:
        return entry.dl_pdu[0]

#############################################################################
############################ Bianry Search ##################################
############################################################################# 
# Find the nearest value in the given list
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

# Find the index of the smallest value that greater than the target
# i.e. a = [1, 4, 7, 7, 13, 13, 19], and binary_search_smallest_greater_index(7, a) = 2
# Input:
# 1. target: value to compare
# 2. base: first index of the range
# 3. sortedList: assume the list has been sorted
def binary_search_smallest_greater_index(target, base, sortedList):
    if sortedList == None:
        return None
    sortedListLen = len(sortedList)
    if sortedListLen == 0:
        return base
    if sortedListLen == 1:
        return base
    if sortedListLen == 2:
        if target <= sortedList[0]:
            return base
        elif target <= sortedList[1]:
            return base + 1
        else:
            return base + 2
    if target > sortedList[sortedListLen/2]:
        return binary_search_smallest_greater_index(target, base + sortedListLen / 2, sortedList[sortedListLen / 2:])
    else:
        return binary_search_smallest_greater_index(target, base, sortedList[:sortedListLen / 2 + 1])

# Find the smallest value that greater than the target
# i.e. a = [1, 4, 7, 10, 13, 16, 19], and binary_search_smallest_greater_value(3, a) = 4
def binary_search_smallest_greater_value(target, sortedList):
    if not sortedList:
        return None
    if target > sortedList[-1]:
        return None
    if target < sortedList[0]:
        return sortedList[0]
    if len(sortedList) == 1:
        return sortedList[0]
    if len(sortedList) == 2:
        return sortedList[1]
    mid = sortedList[len(sortedList)/2]
    if target == mid:
        return mid
    elif target > mid:
        return binary_search_smallest_greater_value(target, sortedList[len(sortedList)/2:])
    else:
        return binary_search_smallest_greater_value(target, sortedList[:len(sortedList)/2+1])

# use binary search to find the largest smaller value that greater than the target
# i.e. a = [1, 4, 7, 10, 13, 16, 19], and binary_search_largest_smaller_value(3, a) = 1
def binary_search_largest_smaller_value(target, sortedList):
    if not sortedList:
        return None
    if target < sortedList[0]:
        return None
    if target > sortedList[-1]:
        return sortedList[-1]
    if len(sortedList) == 1:
        return sortedList[0]
    if len(sortedList) == 2:
        return sortedList[0]
    mid = sortedList[len(sortedList)/2]
    if target == mid:
        return mid
    elif target >= mid:
        return binary_search_largest_smaller_value(target, sortedList[len(sortedList)/2:])
    else:
        return binary_search_largest_smaller_value(target, sortedList[:len(sortedList)/2+1])

#############################################################################
############################ Debugging functions ############################
#############################################################################
# count the total number of a specific type of entry
def count_entry_number(totalEntry, entryID):
    count = 0
    for entry in totalEntry:
        if entry.logID == entryID:
            count += 1

    return count
