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

# Remove duplicated IP packets generated from QXDM
def removeQXDMDupIP(entries):
    check_point_time = time.time()
    if TIME_DEBUG:
        print "Start delete dup IP"

    dupIndex = []
    privEntryIndex = None
    privSignature = None
    # filter all the potential deleted entries
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
def meanStdevPair(li):
    li = [i for i in li if i != 0.0]
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

# use binary search to find the smallest value that greater than the target
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

# merge two dictionaries
# if two dicts have diff key sets, then return the original key set
# else return the merged one
def merge_two_dict(orig_dict, append_dict):
    if sorted(orig_dict.keys()) != sorted(append_dict.keys()):
        return orig_dict
    for key in orig_dict:
        orig_dict[key] += append_dict[key]
    return orig_dict

def convert_ts_in_human(ts):
	return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")

# compute md5 hash
def md5_hash(data):
    # have to put it here to avoid inconsistent hash
    MD5 = hashlib.md5(data)
    return base64.b64encode(MD5.digest(), '._').strip('=')
    # return data
