#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/25/2013
This program print various useful information
"""

import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
from datetime import datetime
import Util as util

DEBUG = False

def printIPaddressPair(entries, threshold):
    #{ip_addr:count,...}
    srcIPCount = {}
    for i in entries:
        if DEBUG:
            print i
        if i.logID == const.PROTOCOL_ID and i.ip["src_ip"] and i.ip["dst_ip"] and i.ip["total_len"] > 60:
            if i.ip["src_ip"] in srcIPCount:
                srcIPCount[i.ip["src_ip"]] += 1
                if srcIPCount[i.ip["src_ip"]] > int(threshold):
                    print "Src IP is %s" % (i.ip["src_ip"])
                    print "Dst IP is %s" % (i.ip["dst_ip"])
                    return
            else:
                srcIPCount[i.ip["src_ip"]] = 1
    print "Not finding proper source ip. Please figure out manually"

# Print RLC retransmission Map
def printRetxCountMapList (countMap):
    for k in sorted(countMap.keys()):
    	for sn, v in countMap[k].items():
        	print "%s\t%d\t%d\t%d" % (util.convert_ts_in_human(k), sn, v[0], v[1])
        	print v[2]

# Given TCP retransmission find the nearest retransmission
def printMapRLCtoTCPRetx (tcpRetxMap, RLCRetxMap):
	# TCP map format: A map of retransmission TCP packet -- {orig_ts: [(orig_entry, retx_entry), (another)]}
	# RLC map format: {ts: {sn1:(count1,duration1, [entries]), sn2:(count2, duration2, [entries]), ...}
	# RLC could 
	ahead_th = 3
	link_ts_sorted = sorted(RLCRetxMap.keys())
	for a in sorted(tcpRetxMap.keys()):
		# TODO: currently use the first one, since retx usually happen not within 1ms
		tcp_delay = tcpRetxMap[a][0][1].timestamp - a
		# TODO: change binary search
		link_ts = 0
		for link_ts in link_ts_sorted:
			if link_ts > a and min([i[1] for i in RLCRetxMap[link_ts].values()]) < tcp_delay:# and link_ts - a < ahead_th:
				break
		rlc_delay = 0
		min_count = 0
		entries = []
		for i in RLCRetxMap[link_ts].values():
			if i[1] > rlc_delay:
				rlc_delay = i[1]
				min_count = i[0]
				entries = i[2]
		#rlc_delay = RLCRetxMap[link_ts].values()[0][1]
		print "%f\t%f\t%f\t%f\t%d\t%d\t%f" % (a, tcp_delay, rlc_delay, abs(link_ts - a), min_count, tcpRetxMap[a][0][0].rrcID, util.meanValue(tcpRetxMap[a][0][0].sig["RSCP"]))


# Print ratio stats of retransmission for each state
# In forms of:
#      ({"tcp_rto": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...}, 
#        "tcp_fast": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_ul": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_dl": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...} ... }, 
#       {"tcp": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_ul": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_dl": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...}})
def printRetxRatio(retxStatsMap, totalStatsMap, retxType):
    result = ""
    totKey = ""
    # track through all the key name in totalMap, if find a string match, then
    # print the whole state ratio of that entry
    for totKey in totalStatsMap:
        if retxType.lower().find(totKey) != -1:
            break
    if retxStatsMap.has_key(retxType.lower()):
        total_count = sum(totalStatsMap[totKey].values())
        if not total_count:
            print "0\t" * len(retxStatsMap[retxType.lower()])
            return
        for k, v in retxStatsMap[retxType.lower()].items():
            ratio = v / total_count
            result += str(ratio) + "\t"
    else:
        print >> sys.stderr, "ERROR: Invalid retransmission type"
        return
    print result

# Deprecated
# Retransmission summary information
def printRetxSummaryInfo (entries, uplinkMap, downlinkMap, tcpMap):
    startTS = None
    ts = None
    totalTCPReTx = 0.0
    totalTCP = 0.0
    totalULReTx = 0.0
    totalUL = 0.0
    totalDLReTx = 0.0
    totalDL = 0.0
    for i in entries:
        if i.rrcID != None:
            if i.logID == const.PROTOCOL_ID or i.logID == const.UL_PDU_ID or \
               i.logID == const.DL_PDU_ID:
                ts = i.timestamp
                if not startTS:
                    startTS = ts      
                RLC_UL_retx_count = 0
                RLC_DL_retx_count = 0
                if i.logID == const.PROTOCOL_ID:
                    totalTCP += 1
                if i.logID == const.UL_PDU_ID:
                    totalUL += len(i.ul_pdu[0]["sn"])
                    if ts in uplinkMap.keys():
                        for sn in i.ul_pdu[0]["sn"]:
                            if uplinkMap[ts].has_key(sn):
                            	#RLC_UL_retx_count = uplinkMap[ts][uplinkMap[ts].index(sn)+1]
                            	RLC_UL_retx_count = uplinkMap[ts][sn][0]
                if i.logID == const.DL_PDU_ID:
                    totalDL += len(i.dl_pdu[0]["sn"])
                    if ts in downlinkMap.keys():
                        #RLC_DL_retx_count = downlinkMap[ts][1]
                        for sn in i.dl_pdu[0]["sn"]:
                            if downlinkMap[ts].has_key(sn):
                                #RLC_DL_retx_count = downlinkMap[ts][downlinkMap[ts].index(sn)+1]
                            	RLC_DL_retx_count = downlinkMap[ts][sn][0]
                totalTCPReTx += int(tcpMap.has_key(ts))
                totalULReTx += RLC_UL_retx_count
                totalDLReTx += RLC_DL_retx_count
                #print "%d\t%d\t%d\t%d\t%d" % (ts, len(i.retx["tp"]), \
                         #RLC_UL_retx_count, RLC_DL_retx_count, i.rrcID)
                         
    # print to stderr for logging
    """
    print >> sys.stderr, "Total TCP retx %f" % (totalTCPReTx)
    print >> sys.stderr, "Total UL retx %f" % (totalULReTx)
    print >> sys.stderr, "Total DL retx %f" % (totalDLReTx)
    if totalULReTx:
        print >> sys.stderr, "TCP/UL: %f" % (totalTCPReTx/totalULReTx)
    else:
        print >> sys.stderr, "TCP/UL: %f" % (0)
    if totalDLReTx:
        print >> sys.stderr, "TCP/DL: %f" % (totalTCPReTx/totalDLReTx)
    else:
        print >> sys.stderr, "TCP/DL: %f" % (0)
    print >> sys.stderr, "TCP retx frequency %f" % (totalTCPReTx/(ts - startTS))
    print >> sys.stderr, "UL frequency %f" % (totalULReTx/(ts - startTS))
    print >> sys.stderr, "DL frequency %f" % (totalDLReTx/(ts - startTS))
    """
    print "Total TCP %d, UL %d, DL %d" % (totalTCP, totalUL, totalDL)
    if totalDL:
        print >> sys.stderr, "%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f" % (totalTCPReTx, totalULReTx, totalDLReTx, totalTCPReTx/totalTCP, totalULReTx/totalUL, totalDLReTx/totalDL, totalTCPReTx/(ts - startTS), totalULReTx/(ts - startTS), totalDLReTx/(ts - startTS))
    else:
        print >> sys.stderr, "%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f" % (totalTCPReTx, totalULReTx, totalDLReTx, totalTCPReTx/totalTCP, totalULReTx/totalUL, 0, totalTCPReTx/(ts - startTS), totalULReTx/(ts - startTS), totalDLReTx/(ts - startTS))

#######################################################################
######################## Context Info #################################
#######################################################################
# energy information
def printRSCP (entries):
    for i in entries:
        if i.rrcID and i.sig["RSCP"]:
            ts = i.timestamp
            print "%f\t%d\t%d" % (ts, util.meanValue(i.sig["RSCP"]), i.rrcID)

# Throughput Information
def printThroughput (entries):
    # Find the maximum throughput for each flow
    # {RRC_state: [throughput, timestamp], ...}
    maxFlowSpeed = {const.FACH_ID: [0.0, None], const.DCH_ID: [0.0, None], const.PCH_ID: [0.0, None]}
    throughputSummary = {const.FACH_ID: [], const.DCH_ID: [], const.PCH_ID: []}
    curFlow = None
    for i in entries:
        if i.rrcID and i.throughput > 0:
            ts = i.timestamp
            if not curFlow:
                curFlow = i.flow
                if maxFlowSpeed[i.rrcID][0] < i.throughput:
                    maxFlowSpeed[i.rrcID][0] = i.throughput
                    maxFlowSpeed[i.rrcID][1] = ts
                continue
            if i.flow == curFlow:
                if maxFlowSpeed[i.rrcID][0] < i.throughput:
                    maxFlowSpeed[i.rrcID][0] = i.throughput
                    maxFlowSpeed[i.rrcID][1] = ts
            else:
                result = []
                for rrc, speed in maxFlowSpeed.items():
                    if speed[1]:
                        result.append("%f\t%f\t%d"%(speed[1], speed[0], rrc))
                for re in sorted(result):
                    print re
                throughputSummary[const.FACH_ID].append(maxFlowSpeed[const.FACH_ID][0])
                throughputSummary[const.DCH_ID].append(maxFlowSpeed[const.DCH_ID][0])
                throughputSummary[const.PCH_ID].append(maxFlowSpeed[const.PCH_ID][0])
                maxFlowSpeed = {const.FACH_ID: [0.0, None], const.DCH_ID: [0.0, None], const.PCH_ID: [0.0, None]}  
                curFlow = i.flow
    print >> sys.stderr, "%f\t%f\t%f" % (util.meanValue(throughputSummary[const.FACH_ID]),\
                                         util.meanValue(throughputSummary[const.DCH_ID]), \
                                         util.meanValue(throughputSummary[const.PCH_ID]),)
### Deprecated
# compute the percentage of sampling period that contains retransmission
# and average retransmission rate
# 
def printRLCReTxMapStats (rlcMap):
	ts_sorted = sorted(rlcMap.keys())
	interval = ts_sorted[1] - ts_sorted[0]
	retx_rate_list = []
	retx_counter = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
	
	for a in ts_sorted:
		if rlcMap[a][0]:
			retx_counter[rlcMap[a][1]] += 1
			retx_rate_list.append(rlcMap[a][0]/interval)
	
	total_num_period = len(ts_sorted)
	total_retx_sample_count = sum(retx_counter.values())
	
	print "Total # of period: %d" % (total_num_period)
	print "%f\t%f\t%f\t%f" % (retx_counter[const.FACH_ID] / total_num_period, \
							  retx_counter[const.DCH_ID] / total_num_period, \
							  retx_counter[const.PCH_ID] / total_num_period, \
							  total_retx_sample_count / total_num_period)
	print "Average retx rate: %d" % util.meanValue(retx_rate_list)
    
#######################################################################
############################## Debug Printer ##########################
#######################################################################
# print the result for UL RLC SN and retransmission count
def printULCount(entries):
    ulMap = {}
    for entry in entries:
        if entry.logID == const.UL_PDU_ID:
            for sn in entry.retx["ul"]:
                if sn in ulMap:
                    ulMap[sn] += len(entry.retx["ul"][sn])
                else:
                    ulMap[sn] = len(entry.retx["ul"][sn])
    
    for u in sorted(ulMap):
        if u >= 3851 and u <= 3886:
            print "UL: %d\t%d" % (u, ulMap[u])
                
# print the result for DL RLC SN and retransmission count
def printDLCount(entries):
    dlMap = {}
    for entry in entries:
        if entry.logID == const.DL_PDU_ID:
            for sn in entry.retx["dl"]:
                if sn in dlMap:
                    dlMap[sn] += len(entry.retx["dl"][sn])
                else:
                    dlMap[sn] = len(entry.retx["dl"][sn])
    
    for u in sorted(dlMap):
        if u >= 3851 and u <= 3886:
            print "DL: %d\t%d" % (u, dlMap[u])

# print a TCP entry information
def printTCPEntry(entry):
	print "%s\t%s\t%s\t%s\t%s\t%d\t%d" % (util.convert_ts_in_human(entry.timestamp),\
	 					entry.ip["src_ip"], entry.ip["dst_ip"], hex(entry.tcp["seq_num"]), \
	 					hex(entry.tcp["ack_num"]), entry.ip["total_len"], entry.tcp["seg_size"])
	 
