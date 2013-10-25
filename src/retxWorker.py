#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/01/2013

It contains all the necessary functions to process TCP and RLC retransmission
"""
import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
import PrintWrapper as pw
import Util as util
from datetime import datetime

DEBUG = False
CUR_DEBUG = False
RETX_DEBUG = True
############################################################################
############################# TCP Retx #####################################
############################################################################
# Always assume the first packet start with a SYN_NON_ACK packet
# extract the data entry based on flow info
# @Return [[flow1_of_entries], [flow2_of_entries], ...]
def extractFlows (entries):
    flows = []
    localFlow = []
    for entry in entries:
        if entry.logID == const.PROTOCOL_ID and entry.ip["tlp_id"] == const.TCP_ID:
            # if not entry.flow:
            if not (entry.tcp["SYN_FLAG"] and not entry.tcp["ACK_FLAG"]):
                localFlow.append(entry)
            elif localFlow:
                # start a new flow here
                flows.append(localFlow)
                localFlow = [entry]
            else:
                # When the first packet is SYN packet
                localFlow = [entry]
    if localFlow:
        flows.append(localFlow)
    return flows

#########
# NOTICE: include the one TCP packet after the last retransmission at the end of the retransmission
# @return: TCP retx map -- {orig_ts: [[orig_entry, retx_entry, 2nd_retx_entry], entry_after_last_retx], next_ts: [[entry_list, ...], entry_right_after]}
#   1. RTO map  2. Fast retx Map    3. Union of the previous two
def procTCPReTx (flows, direction, srv_ip):
    is_up = True
    if direction.lower() != "up":
        is_up = False
    # RTO and fast retx map
    tcpReTxMap = {}
    tcpFastReTxMap = {}
    tcpOverallRetxMap = {}  # basically a combine of RTO and fast retx map

    for flow in flows:
        startPosition = findDataFlowStartIndex(flow)
        data_pkts = flow[startPosition:]
        # keep a list of previous packets which doesn't include retx and fast retx packets
        priv_pkts = []
        for i in range(len(data_pkts)):
            # Exam fast retransmission first, then check wether it is a RTO
            orig_fast_retx_entry = detectFastReTx(data_pkts[i], priv_pkts, is_up, srv_ip)
            if orig_fast_retx_entry:
                # assume retransmission entry will have different timestamp
                if orig_fast_retx_entry.timestamp in tcpFastReTxMap:
                    # Handle multiple retransmission
                    exist_orig_group = tcpFastReTxMap[orig_fast_retx_entry.timestamp][0]
                    if exist_orig_group[0] == orig_fast_retx_entry:
                        exist_orig_group.append(data_pkts[i])
                        # update the last entry after the this retransmission packet
                        exist_orig_group[1] = findNextEntry(data_pkts[i], data_pkts[i+1:])
                else:
                    tcpFastReTxMap[orig_fast_retx_entry.timestamp] = [[orig_fast_retx_entry, data_pkts[i]], \
                                   findNextEntry(data_pkts[i], data_pkts[i+1:])]
                    tcpOverallRetxMap[orig_fast_retx_entry.timestamp] = [[orig_fast_retx_entry, data_pkts[i]], \
                                      findNextEntry(data_pkts[i], data_pkts[i+1:])]
            else:
                orig_entry = detectReTx(data_pkts[i], priv_pkts, is_up, srv_ip)
                if orig_entry:
                    # assume retransmission entry will have different timestamp
                    if orig_entry.timestamp in tcpReTxMap:
                        # Handle multiple retransmission
                        exist_orig_group = tcpReTxMap[orig_entry.timestamp][0]
                        if exist_orig_group[0] == orig_entry:
                            exist_orig_group.append(data_pkts[i])
                            # update the last entry after the this retransmission packet
                            exist_orig_group[1] = findNextEntry(data_pkts[i], data_pkts[i+1:])
                    else:
                        tcpReTxMap[orig_entry.timestamp] = [[orig_entry, data_pkts[i]], \
                                   findNextEntry(data_pkts[i], data_pkts[i+1:])]
                        tcpOverallRetxMap[orig_entry.timestamp] = [[orig_entry, data_pkts[i]], \
                                          findNextEntry(data_pkts[i], data_pkts[i+1:])]
                else:
                    priv_pkts.append(data_pkts[i])     

    return (tcpReTxMap, tcpFastReTxMap, tcpOverallRetxMap)

# check if an entry is a fast retransmission packet by detecting the existance
# of duplicate ACKs in the reverse trace.
# @ Return: entry -- original packet with the same sequence number
#           False -- fail to find one
def detectFastReTx (entry, entryHist, is_up, srv_ip):
    ack_count = 0
    detectFastReTx = False

    # fast decline if sequence number is increasing
    if (is_up and entry.ip["dst_ip"] != srv_ip) or \
       (not is_up and entry.ip["src_ip"] != srv_ip) or \
       entry.tcp["seg_size"] <= 0:
    	return False   

    # TODO: debug with packet of interest
    target = False
    if DEBUG:
        if util.convert_ts_in_human(entry.timestamp) == "11:00:28.738000":
            print "!!!FIND THE TARGET!!!"
            pw.printTCPEntry(entry)
            print "Priv entries length is %d" % len(entryHist[::-1])
            target = True

    for i in entryHist[::-1]:
        """
    	if (entry.ip["src_ip"] != i.ip["dst_ip"] or \
           entry.ip["dst_ip"] != i.ip["src_ip"]):
            continue
        """ 
        # print number of dup ack it encounterd
        if DEBUG and target:
            print "[=" * 40
            pw.printTCPEntry(i)
            print "# ack number is %d" % ack_count
            print "Find dup ack is %s" % detectFastReTx
            print "=]" * 40
        # Make sure we are in the opposite direction when we haven't detect a fast retx
        if not detectFastReTx and \
           (entry.ip["src_ip"] != i.ip["dst_ip"] or \
           entry.ip["dst_ip"] != i.ip["src_ip"]):
            continue
        # when we have found the fast retransmission, return the nearest entry 
        # with smaller or equivalent seq_num
        elif detectFastReTx:
            if entry.ip["src_ip"] == i.ip["src_ip"] and \
               entry.ip["dst_ip"] == i.ip["dst_ip"]:
                if entry.tcp["seq_num"] == i.tcp["seq_num"]:
                    # TODO: debug
                    if DEBUG:
                        print "$" * 40
                        print "Detect fast retransmission"
                        print "Ongoing pkt:"
                        pw.printTCPEntry(entry)
                        print "Checking pkt:"
                        pw.printTCPEntry(i)
                    return i
                elif entry.tcp["seq_num"] > i.tcp["seq_num"]:
                    break
            else:
                continue

        # Track the most recent 3 ACKs
        if ((is_up and i.ip["src_ip"] == srv_ip) or \
           (not is_up and i.ip["dst_ip"] == srv_ip)) and \
           i.tcp["seg_size"] == 0:
            # fast decline by detecting a smaller ack number
            if entry.tcp["seq_num"] != i.tcp["ack_num"]:
    	        return False
            else:
                ack_count += 1
        
        if ack_count >= const.FAST_RETX_COUNT:
            detectFastReTx = True
            # return i

    return False

# check if an entry is a retransmission
# Use sequnence number to trace back the original information
# @return False -- Fail to find a duplicate packet
#		  Entry -- the original packet with the same sequence number
def detectReTx (entry, entryHist, is_up, srv_ip):
    if (is_up and entry.ip["dst_ip"] != srv_ip) or \
       (not is_up and entry.ip["src_ip"] != srv_ip) or \
       entry.tcp["seg_size"] <= 0:          
        return False
	
    for i in entryHist[::-1]:
        #####
        # Make sure we are in the same direction
        if entry.ip["src_ip"] != i.ip["src_ip"] or \
           entry.ip["dst_ip"] != i.ip["dst_ip"]:
            continue
        # fast decline if sequence number is increasing
        if entry.tcp["seq_num"] > i.tcp["seq_num"] or \
           entry.tcp["FIN_FLAG"]:
            return False
        if i.tcp["seg_size"] > 0 and \
           entry.tcp["seq_num"] == i.tcp["seq_num"]:
           # entry.tcp["flags"] == i.tcp["flags"]
           # entry.ip["total_len"] == i.ip["total_len"]:
           #and entry.tcp["payload"] == i.tcp["payload"]:
           # TODO: debug
            if DEBUG:
                print "Original:"
                pw.printTCPEntry(i)
                print "Retx:"
                pw.printTCPEntry(entry)
            privTS = i.timestamp
            ts = entry.timestamp
            return i
    return False

############################################################################
############################# RLC Retx #####################################
############################################################################
# process link layer retransmission
# INPUT:
# 1. entries: list of the QxDM entries
# 2. detail: the detail level of output, i.e. simple or complete
# 
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
# 
# NOTICE:
# Only retransmissted packet PDU is in the map
#
# TODO: Fix the downlink part, currenly using heuristics
def procRLCReTx(entries, detail="complete"):
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
    
    count = 0;

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
                    count += 1
                    if curSN_UL not in ULReTxCountMapLocal:
                    	# [retx_count, timestamp, duration]
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
        # TODO: fix the correctness of downlink
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
                    	# [retx_count, timestamp, duration]
                        DLReTxCountMapLocal[curSN_DL] = [0, ts_dl, ts_dl - DLSNMap[curSN_DL][1], [DLSNMap[curSN_DL][2], entry]]
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

    # TODO: delete after debugging
    if RETX_DEBUG:
        print "RetxWorker: # of RLC entries inserted is " + str(count)

    if detail == "simple":
        return [retxCountSimpleTransform(ULReTxCountMapList), \
                retxCountSimpleTransform(DLReTxCountMapList)]

    return [retxCountMapTransform(ULReTxCountMapList), \
            retxCountMapTransform(DLReTxCountMapList)]

############################################################################
############################# Statistic Info ###############################
############################################################################
# Collect TCP and RLC retx statistic info
# Return one map of retx count vs RRC state, the other one is total count vs rrc state
# Since we always assume you perform the task in one direction,
# we only count tcp in one direction
# In forms of:
# 1. Retx Count Map
#      ({"tcp_rto": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...}, 
#        "tcp_fast": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_ul": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_dl": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...} ... }, 
# 2. Total Count Map 
#       {"tcp_rto": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...}, 
#        "tcp_fast": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_ul": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_dl": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...}})
# 3. Retx RTT Map
#       {"tcp_rto": {TODO}, 
#        "tcp_fast": {TODO},
#        "rlc_ul": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_dl": {TODO}})
# 4. total RTT Map:
#       {"tcp_rto": {TODO}, 
#        "tcp_fast": {TODO},
#        "rlc_ul": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_dl": {TODO}})
# TODO: adjust to finer granularity of state later
def collectReTxPlusRRCResult (entries, tcpRetxMap, tcpFastRetxMap):
    ######
    ## Occurance count
    RLC_UL_retx = initFullRRCMap(0.0)
    RLC_DL_retx = initFullRRCMap(0.0)
    RLC_UL_tot_pkts = initFullRRCMap(0.0)
    RLC_DL_tot_pkts = initFullRRCMap(0.0)
    TCP_rto_retx = initFullRRCMap(0.0)
    TCP_fast_retx = initFullRRCMap(0.0)
    TCP_total_count = initFullRRCMap(0.0)

    rrc_state = initFullRRCMap(0.0)

    ######
    ## Bytes Count
    TCP_rto_retx_bytes = initFullRRCMap(0.0)
    TCP_fast_retx_bytes = initFullRRCMap(0.0)
    RLC_UL_bytes = initFullRRCMap(0.0)
    RLC_DL_bytes =  initFullRRCMap(0.0)
    ULBytes_total = 0.0
    DLBytes_total = 0.0
    Bytes_on_fly = 0.0

    ######
    ## retx RTT Map
    TCP_rto_RTT = initFullRRCMap(0.0)
    TCP_fast_retx_RTT = initFullRRCMap(0.0)
    RLC_UL_RETX_RTT = initFullRRCMap(0.0)
    RLC_DL_RETX_RTT = initFullRRCMap(0.0)

    ######
    ## overall RTT Map
    TCP_rto_TOT_RTT = initFullRRCMap(0.0)
    TCP_fast_retx_TOT_RTT = initFullRRCMap(0.0)
    RLC_UL_TOT_RTT = initFullRRCMap(0.0)
    RLC_DL_TOT_RTT = initFullRRCMap(0.0)

    count_total_fach_promote = 0.0
    count_total_fach = 0.0
    count_fach_promote_retx = 0.0
    count_fach_retx = 0.0

    for i in entries:
        ts = i.timestamp
        """
        if i.eul["t2p_ec"] != None and i.eul["t2p_ed"] != None:
            print "%f\t%f\t%f" % (ts, i.eul["t2p_ec"], i.eul["t2p_ed"])
        if i.eul["raw_bit_rate"] != None:
            print "%f\t%f" % (ts, i.eul["raw_bit_rate"])
        """
        if i.rrcID != None and i.rrcID in const.RRC_MAP.keys():
            # print "%f\t%d\t%d\t%d" % (ts, i.rrcID, sum([len(x) for x in i.retx["ul"].values()]), \
            #                          sum([len(x) for x in i.retx["dl"].values()]))
            # Timestamp Trans_RT_BYTES UL_RT_BYTES DL_RT_BYTES rrc
            if i.logID == const.PROTOCOL_ID or i.logID == const.UL_PDU_ID or \
               i.logID == const.DL_PDU_ID:
                if 0:
                    print "%f\t%d\t%d\t%d\t%d" % (ts, len(i.retx["tp"]), sum([len(x) for x in i.retx["ul"].values()]), \
                          sum([len(x) for x in i.retx["dl"].values()]), i.rrcID)
                else:
                    pass
            if CUR_DEBUG:
                if i.rrcID == const.FACH_TO_DCH_ID: 
                    count_total_fach_promote += 1
                if i.rrcID == const.FACH_ID:
                    count_total_fach += 1
            rrc_state[i.rrcID] += 1
            cur_ul_retx_count = sum([len(x) for x in i.retx["ul"].values()])
            cur_dl_retx_count = sum([len(x) for x in i.retx["dl"].values()])
            RLC_UL_retx[i.rrcID] += cur_ul_retx_count
            RLC_DL_retx[i.rrcID] += cur_dl_retx_count
            if i.logID == const.PROTOCOL_ID:
                Bytes_on_fly += i.ip["total_len"]
                TCP_total_count[i.rrcID] += 1
                if tcpRetxMap and tcpRetxMap.has_key(ts):
                    TCP_rto_retx_bytes[i.rrcID] += i.ip["total_len"] 
                    TCP_rto_retx[i.rrcID] += 1
                if tcpFastRetxMap and tcpFastRetxMap.has_key(ts):
                    TCP_fast_retx_bytes[i.rrcID] += i.ip["total_len"]
                    TCP_fast_retx[i.rrcID] += 1
            if i.logID == const.UL_PDU_ID:
                ULBytes_total += sum(i.ul_pdu[0]["size"])
                RLC_UL_tot_pkts[i.rrcID] += i.ul_pdu[0]["numPDU"]
                if i.rtt["rlc"]:
                    RLC_UL_TOT_RTT[i.rrcID] += i.ul_pdu[0]["numPDU"] * i.rtt["rlc"]
                if i.retx["ul"]:
                    RLC_UL_bytes[i.rrcID] += sum([sum(x) for x in i.retx["ul"].values()])
                    if i.rtt["rlc"]:
                        RLC_UL_RETX_RTT[i.rrcID] += cur_ul_retx_count * i.rtt["rlc"]
                    if CUR_DEBUG:
                        if i.rrcID == const.FACH_TO_DCH_ID: 
                            count_fach_promote_retx += 1
                        if i.rrcID == const.FACH_ID:
                            count_fach_retx += 1
            if i.logID == const.DL_PDU_ID:
                DLBytes_total += sum(i.dl_pdu[0]["size"])
                RLC_DL_tot_pkts[i.rrcID] += i.dl_pdu[0]["numPDU"]
                if i.retx["dl"]:
                    RLC_DL_bytes[i.rrcID] += sum([sum(x) for x in i.retx["dl"].values()])

    # assign the map    
    retx_count_map = {"tcp_rto": TCP_rto_retx, "tcp_fast": TCP_fast_retx, "rlc_ul": RLC_UL_retx, "rlc_dl":RLC_DL_retx}
    total_count_map = {"tcp_rto": TCP_total_count, "tcp_fast": TCP_total_count, "rlc_ul": RLC_UL_tot_pkts, "rlc_dl": RLC_DL_tot_pkts}
    rtt_retx_map = {"tcp_rto": TCP_rto_RTT, "tcp_fast": TCP_fast_retx_RTT, "rlc_ul": RLC_UL_RETX_RTT, "rlc_dl": RLC_DL_RETX_RTT}
    rtt_overall_map = {"tcp_rto": TCP_rto_TOT_RTT, "tcp_fast": TCP_fast_retx_TOT_RTT, "rlc_ul": RLC_UL_TOT_RTT, "rlc_dl": RLC_DL_TOT_RTT}
    
    if CUR_DEBUG:
        if count_total_fach_promote:
            print "FACH promote ratio %f" % (count_fach_promote_retx/(count_total_fach_promote))
            # print "Stable FACH retransmission ratio %f " % (count_fach_retx / (count_total_fach_promote))
        else:
            print "FACH promote ratio %f" % (0)
    return (retx_count_map, total_count_map, rtt_retx_map, rtt_overall_map)

    # print "***************"
    totUL = float(sum(RLC_UL_retx))
    totDL = float(sum(RLC_DL_retx))
    totState = float(sum(rrc_state))
    totULBytes = float(sum(RLC_UL_bytes))
    totDLBytes = float(sum(RLC_DL_bytes))
    totRLCUL = float(sum(RLC_UL_tot_pkts.values()))
    totRLCDL = float(sum(RLC_DL_tot_pkts.values()))
    # Retransmission number
    #print "%d\t%d" % (totUL, totDL)
    # Retransmission break down
    # print "%d\t%d\t%d\t%d\t%d\t%d" % (RLC_UL_retx[const.FACH_ID], RLC_UL_retx[const.DCH_ID], RLC_UL_retx[const.PCH_ID], RLC_DL_retx[const.FACH_ID], RLC_DL_retx[const.DCH_ID], RLC_DL_retx[const.PCH_ID])
    #if totDL != 0:
	    #print "%f\t%f\t%f\t%f\t%f\t%f" % (RLC_UL_retx[const.FACH_ID] / totUL, RLC_UL_retx[const.DCH_ID] / totUL, RLC_UL_retx[const.PCH_ID] / totUL, RLC_DL_retx[const.FACH_ID] / totDL, RLC_DL_retx[const.DCH_ID] / totDL, RLC_DL_retx[const.PCH_ID] / totDL)
    #else:
		#print "%f\t%f\t%f\t0\t0\t0" % (RLC_UL_retx[const.FACH_ID] / totUL, RLC_UL_retx[const.DCH_ID] / totUL, RLC_UL_retx[const.PCH_ID] / totUL)
    # Retransmission fraction IP
    #if Bytes_on_fly != 0:
        #print "%f" % (Trans_retx_bytes)
        #print "%f" % (TCP_retx_count)
        #print "%f" % (Trans_retx_bytes/Bytes_on_fly)
    # Retransmission on link layer (UL \t DL)
    #if ULBytes_total + DLBytes_total != 0:
        #print "%f\t%f" % (totULBytes, totDLBytes)
        # print "%f\t%f" % (totULBytes/(ULBytes_total + DLBytes_total), totDLBytes/(ULBytes_total + DLBytes_total))
    # Total RLC packets break down
    print "%f\t%f\t%f\t%f\t%f\t%f" % (RLC_UL_tot_pkts[const.FACH_ID] / totRLCUL, RLC_UL_tot_pkts[const.DCH_ID] / totRLCUL, RLC_UL_tot_pkts[const.PCH_ID] / totRLCUL, RLC_DL_tot_pkts[const.FACH_ID] / totRLCDL, RLC_DL_tot_pkts[const.DCH_ID] / totRLCDL, RLC_DL_tot_pkts[const.PCH_ID] / totRLCDL)
    print "%f\t%f\t%f\t%f\t%f\t%f" % (RLC_UL_tot_pkts[const.FACH_ID], RLC_UL_tot_pkts[const.DCH_ID], RLC_UL_tot_pkts[const.PCH_ID], RLC_DL_tot_pkts[const.FACH_ID], RLC_DL_tot_pkts[const.DCH_ID], RLC_DL_tot_pkts[const.PCH_ID])

############################################################################
###################### Helper Functions ####################################
############################################################################
# return a dict with all existing RRC state as keys, with value 0.0
def initFullRRCMap(init_value):
    return initFullRRCMap(init_value, const.RRC_MAP)

def initFullRRCMap(init_value, rrc_map = const.RRC_MAP):
    initMap = {}
    for i in rrc_map.keys():
        if isinstance(init_value, list):
            initMap[i] = list(init_value)
        elif isinstance(init_value, dict):
            initMap[i] = dict(init_value)
        else:
            initMap[i] = init_value
    return initMap

# basic idea is to find the first ACK that 
def findDataFlowStartIndex(flow):
	for i in range(len(flow)):
		if flow[i].tcp["ACK_FLAG"] and not flow[i].tcp["SYN_FLAG"] and \
		   flow[i].tcp["seg_size"] == 0 and flow[i].tcp["seq_num"] == flow[0].tcp["seq_num"] + 1:
		   	return i+1
	return 0

# find the last entry next to the last ACK
def findNextEntry(cur_entry, rest_flow):
    for i in rest_flow:
        if cur_entry.ip["src_ip"] == i.ip["src_ip"] and \
           cur_entry.ip["dst_ip"] == i.ip["dst_ip"] and \
           i.tcp["seg_size"] > 0:
            return i        
    return None
    

# Count the TCP retransmission
def countTCPReTx(tcpRetxMap):
	return sum([len(i[0])-1 for i in tcpRetxMap.values()])

# Transform the ReTx Count map into Timestamp key base
# Old format: {sn: [count, ts, duration, entry]}
# New format: {ts: {sn1:(count1,duration1, [entry1, entry2,...]), sn2:(count2, duration2, [entry1, entry2, ...]), ...}
# Also inject retransmitted entry into the count
def retxCountMapTransform (retxCountMapList):
    tsMap = {}
    for retxCountMap in retxCountMapList:
        for k, v in retxCountMap.items():
            if v[1] in tsMap:
                tsMap[v[1]][k] = (v[0], v[2], v[3])
            else:
                tsMap[v[1]] = {k: (v[0], v[2], v[3])}
            for retxEntry in v[3]:
                if retxEntry.timestamp in tsMap:
                    tsMap[retxEntry.timestamp][k] = (v[0], v[2], [])
                else:
                    tsMap[retxEntry.timestamp] = {k: (v[0], v[2], [])}
    return tsMap

# Simple output format
# input format: {sn: [count, ts, duration, entry]}
# output format: {entry: {sn: count,...},...}
def retxCountSimpleTransform(snBasedMapList):
    entryBasedMap = {}

    for snBasedMap in snBasedMapList:
        for k, v in snBasedMap.items():
            for entry in v[3]:
                if not entryBasedMap.has_key(entry):
                    entryBasedMap[entry] = {}
                entryBasedMap[entry][k] = v[0]

    return entryBasedMap
