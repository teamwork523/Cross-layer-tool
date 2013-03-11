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

def printIPaddressPair(entries, threshold):
    #{ip_addr:count,...}
    srcIPCount = {}
    for i in entries:
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

# Signal strength vs. Link layer ReTx 
def printRSSIvsLinkReTx (entries):
    # assume assign AGC already
    rssi_list_all = []
    rssi_list_retx = []
    for i in entries:
        ts = i.timestamp
        # Consider only downlink
        if i.logID == const.DL_PDU_ID:
            if i.rssi["Rx"]:
                rssi_list_all.append(i.rssi["Rx"])
                if i.retx["dl"] != 0:
                    # print "%f\t%f" % (ts, i.rssi["Rx"])
                    rssi_list_retx.append(i.rssi["Rx"])
    print "Link: Avg Total rssi is %f" % (util.meanValue(rssi_list_all))
    print "Link: Avg ReTx rssi is %f" % (util.meanValue(rssi_list_retx))
    print "Link: Median Total rssi is %f" % (util.medianValue(rssi_list_all))
    print "Link: Median ReTx rssi is %f" % (util.medianValue(rssi_list_retx))

# Signal strength vs. Transport layer ReTx
def printRSSIvsTransReTx (entries):
    # assume assigne AGC already
    rssi_list_all = []
    rssi_list_retx = []
    for i in entries:
        ts = i.timestamp
        if i.logID == const.PROTOCOL_ID:
            if i.rssi["Rx"]:
                rssi_list_all.append(i.rssi["Rx"])
                if i.retx["tp"] != 0:
                    # print "%f\t%f" % (ts, i.rssi["Rx"])
                    rssi_list_retx.append(i.rssi["Rx"])
    print "Trans: Avg Total rssi is %f" % (util.meanValue(rssi_list_all))
    print "Trans: Avg ReTx rssi is %f" % (util.meanValue(rssi_list_retx))
    print "Trans: Median Total rssi is %f" % (util.medianValue(rssi_list_all))
    print "Trans: Median ReTx rssi is %f" % (util.medianValue(rssi_list_retx))

# Print RLC retransmission Map
def printRetxCountMapList (countMap):
    for k in sorted(countMap.keys()):
    	for sn, v in countMap[k].items():
        	print "%s\t%d\t%d\t%d" % (util.convert_ts_in_human(k), sn, v[0], v[1])
        	print v[2]

# Given TCP retransmission find the nearest retransmission
def printTwoRetx (tcpRetxMap, RLCRetxMap):
	# TCP map format: A map of retransmission TCP packet -- {orig_ts: [(orig_entry, retx_entry), (another)]}
	# RLC map format: {ts: {sn1:(count1,duration1, entry), sn2:(count2, duration2, entry), ...}
	link_ts_sorted = sorted(RLCRetxMap.keys())
	for a in sorted(tcpRetxMap.keys()):
		# TODO: currently use the first one, since retx usually happen not within 1ms
		tcp_delay = tcpRetxMap[a][0][1].timestamp - a
		link_ts = util.binarySearch(a, link_ts_sorted)
		# rlc_delay = max([i[1] for i in RLCRetxMap[link_ts].values()])
		rlc_delay = RLCRetxMap[link_ts].values()[0][1]
		print "%f\t%f\t%f\t%f\t%d\t%f" % (a, tcp_delay, rlc_delay, abs(link_ts - a), tcpRetxMap[a][0][0].rrcID, util.meanValue(tcpRetxMap[a][0][0].sig["RSCP"]))

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

# Print Retransmission vs RRC state
def printReTxVSRRCResult (entries):
    ULBytes_total = 0.0
    DLBytes_total = 0.0
    ReTxUL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    ReTxDL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    rrc_state = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    Bytes_on_fly = 0.0
    TCP_retx_count = 0
    TCP_total_count = 0
    Trans_retx_bytes = 0.0
    retxul_bytes = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    retxdl_bytes =  {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    for i in entries:
        ts = i.timestamp
        """
        if i.eul["t2p_ec"] != None and i.eul["t2p_ed"] != None:
            print "%f\t%f\t%f" % (ts, i.eul["t2p_ec"], i.eul["t2p_ed"])
        if i.eul["raw_bit_rate"] != None:
            print "%f\t%f" % (ts, i.eul["raw_bit_rate"])
        """
        if i.rrcID != None:
            # print "%f\t%d\t%d\t%d" % (ts, i.rrcID, sum([len(x) for x in i.retx["ul"].values()]), \
            #                          sum([len(x) for x in i.retx["dl"].values()]))
            # Timestamp Trans_RT_BYTES UL_RT_BYTES DL_RT_BYTES rrc
            if i.logID == const.PROTOCOL_ID or i.logID == const.UL_PDU_ID or \
               i.logID == const.DL_PDU_ID:
                #print "%f\t%d\t%d\t%d\t%d" % (ts, len(i.retx["tp"]), sum([len(x) for x in i.retx["ul"].values()]), \
                      # sum([len(x) for x in i.retx["dl"].values()]), i.rrcID)
                pass
            rrc_state[i.rrcID] += 1
            ReTxUL[i.rrcID] += sum([len(x) for x in i.retx["ul"].values()])
            ReTxDL[i.rrcID] += sum([len(x) for x in i.retx["dl"].values()])
            if i.logID == const.PROTOCOL_ID:
                Bytes_on_fly += i.ip["total_len"]
                TCP_total_count += 1
                if i.retx["tp"]:
                    Trans_retx_bytes += i.ip["total_len"] 
                    TCP_retx_count += 1               
            if i.logID == const.UL_PDU_ID:
                ULBytes_total += sum(i.ul_pdu[0]["size"])
                if i.retx["ul"]:
                    retxul_bytes[i.rrcID] += sum([sum(x) for x in i.retx["ul"].values()])
            if i.logID == const.DL_PDU_ID:
                DLBytes_total += sum(i.dl_pdu[0]["size"])
                if i.retx["dl"]:
                    retxdl_bytes[i.rrcID] += sum([sum(x) for x in i.retx["dl"].values()])
            
    # print "***************"
    totUL = float(ReTxUL[2]+ReTxUL[3]+ReTxUL[4])
    totDL = float(ReTxDL[2]+ReTxDL[3]+ReTxDL[4])
    totState = float(rrc_state[2]+rrc_state[3]+rrc_state[4])
    totULBytes = float(retxul_bytes[2]+retxul_bytes[3]+retxul_bytes[4])
    totDLBytes = float(retxdl_bytes[2]+retxdl_bytes[3]+retxdl_bytes[4])
    # Retransmission number
    #print "%d\t%d" % (totUL, totDL)
    # Retransmission break down
    print "%d\t%d\t%d\t%d\t%d\t%d" % (ReTxUL[const.FACH_ID], ReTxUL[const.DCH_ID], ReTxUL[const.PCH_ID], ReTxDL[const.FACH_ID], ReTxDL[const.DCH_ID], ReTxDL[const.PCH_ID])
    # Retransmission fraction IP
    #if Bytes_on_fly != 0:
        #print "%f" % (Trans_retx_bytes)
        #print "%f" % (TCP_retx_count)
        #print "%f" % (Trans_retx_bytes/Bytes_on_fly)
    # Retransmission on link layer (UL \t DL)
    #if ULBytes_total + DLBytes_total != 0:
        #print "%f\t%f" % (totULBytes, totDLBytes)
        # print "%f\t%f" % (totULBytes/(ULBytes_total + DLBytes_total), totDLBytes/(ULBytes_total + DLBytes_total))
    # Retransmission number by direction
    
"""
    print "Total UL retx: %f" % (totUL)
    print "Total DL retx: %f" % (totDL)
    print "Total RRC state: %f" % (totState)

    print "Total bytes on fly: %f" % (Bytes_on_fly)
    print "Total retx bytes on IP: %f" % (Trans_retx_bytes)
    print "Total Uplink bytes: %d" % (ULBytes_total)
    print "Total Downlink bytes: %d" % (DLBytes_total)
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

############################## Debug Printer #########################
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

# print a entry information
def printEntry(entry):
	print "%s\t%s\t%s\t%s\t%s\t%d" % (util.convert_ts_in_human(entry.timestamp),\
	 					entry.ip["src_ip"], entry.ip["dst_ip"], hex(entry.tcp["seq_num"]), \
	 					hex(entry.tcp["ack_num"]), entry.ip["total_len"])
