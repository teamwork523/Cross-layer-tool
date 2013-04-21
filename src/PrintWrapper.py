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
import crossLayerWorker as clw
from datetime import datetime
import Util as util

DEBUG = True
BINARY_SEARCH = True

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

#######################################################################
########################### Loss Related ##############################
#######################################################################
# print loss rate based on each RRC state
def print_loss_ratio_per_state (loss_count_per_state_map, loss_total_per_state_map):
    total_loss_udp= sum(loss_count_per_state_map.values())
    total_udp = sum(loss_total_per_state_map.values())
    loss_result = ""
    per_state_loss_result = ""
    per_state_loss_ratio_result = ""

    if total_udp:
        for k,v in loss_count_per_state_map.items():
            loss_result += str(v / total_udp) + "\t"
            per_state_loss_result += str(v) + "\t"
            per_state_loss_ratio = 0
            if loss_total_per_state_map[k]:
                per_state_loss_ratio = v/loss_total_per_state_map[k]
            per_state_loss_ratio_result += str(per_state_loss_ratio) + "\t"
    else: 
        loss_result = "0\t" * len(loss_total_per_state_map)
    
    print "Total UDP: %d" % total_udp
    print "Total loss UDP: %d" % total_loss_udp
    print "Overall loss Ratio: %f" % (total_loss_udp / total_udp)
    print "Overall loss per state Ratio:"
    print loss_result
    print "Per state Loss Count:"
    print per_state_loss_result
    print "Per state Loss Ratio:"
    print per_state_loss_ratio_result

# print a loss case
def print_loss_case(QCATEntries, loss_index, rlc_retx_index_list):
    UDP_entry = QCATEntries[loss_index]
    baseTime = UDP_entry.timestamp
    print "%f\t%f\t%f" % (0,UDP_entry.rrcID,0)
    for index in rlc_retx_index_list:
        cur_entry = QCATEntries[index]
        diff_time = cur_entry.timestamp -baseTime                                                                                                                                                                                                                                                                                      
        print "%f\t%f\t%f" % (diff_time, 0, cur_entry.rrcID)

#######################################################################
########################### Retx Related ##############################
#######################################################################
# Print RLC retransmission Map
def printRetxCountMapList (countMap):
    for k in sorted(countMap.keys()):
    	for sn, v in countMap[k].items():
        	print "%s\t%d\t%d\t%d" % (util.convert_ts_in_human(k), sn, v[0], v[1])
        	print v[2]

# Given TCP retransmission find the nearest retransmission
def printmap_SDU_to_PDURetx (tcpRetxMap, RLCRetxMap):
    # TCP map format: A map of retransmission TCP packet -- {orig_ts: [(orig_entry, retx_entry, 2nd_retx_entry...), (another)]}
    # RLC map format: {ts: {sn1:(count1,duration1, [entries]), sn2:(count2, duration2, [entries]), ...}
    ahead_th = 3
    link_ts_sorted = sorted(RLCRetxMap.keys())
    for a in sorted(tcpRetxMap.keys()):
        # TODO: currently use the first one, since retx usually happen not within 1ms
        tcp_delay = tcpRetxMap[a][0][-1].timestamp - a
        # TODO: change binary search
        if BINARY_SEARCH:
            link_ts = util.binarySearch(a, link_ts_sorted)
        else:
            link_ts = 0
            for link_ts in link_ts_sorted:
                if link_ts > a and min([i[1] for i in RLCRetxMap[link_ts].values()]) < tcp_delay: # and link_ts - a < ahead_th:
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
        print "%f\t%f\t%f\t%f\t%d\t%d\t%f" % (a, tcp_delay, rlc_delay, abs(link_ts - a), min_count, tcpRetxMap[a][0][0].rrcID, util.medianValue(tcpRetxMap[a][0][0].sig["RSCP"]))

    if DEBUG:
        totalCount = 0.0
        totalDuration = 0.0
        for dic in RLCRetxMap.values():
            for v in dic.values():
                totalCount += 1
                totalDuration += v[1]
        if totalCount:
            print "Retrans duration: %f\n" % (totalDuration / totalCount) 
        else:
            print "Retrans duration: %f\n" % (0)


# Print retransmission count and RTT ratio for each state
# In forms of:
#      ({"tcp_rto": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...}, 
#        "tcp_fast": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_ul": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...},
#        "rlc_dl": {RRC_state_1: retx_count1, RRC_state_2: retx_count2, ...} ... }, 
#       {"tcp_rto": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "tcp_fast": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_ul": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...},
#        "rlc_dl": {RRC_state_1: total_count1, RRC_state_2: total_count2, ...}})
def printRetxRatio(retxStatsMap, totalStatsMap, retxRTTMap, totalRTTMap, retxType):
    # RTT result    
    rtt_result = ""
    rtt_per_state_ratio_result = ""
    rtt_per_state_result = ""
    rtt_tot_result = ""

    # Count result
    count_result = ""
    tot_result = ""
    totKey = ""
    per_state_ratio = ""
    per_state_count = ""
    # track through all the key name in totalMap, if find a string match, then
    # print the whole state ratio of that entry
    for totKey in totalStatsMap:
        if retxType.lower().find(totKey) != -1:
            break
    if retxStatsMap.has_key(retxType.lower()):
        # We need to exclude the retransmitted packets as total
        total_count = sum(totalStatsMap[totKey].values()) - sum(retxStatsMap[totKey].values())
        total_rtt = sum(totalRTTMap[totKey].values()) - sum(retxRTTMap[totKey].values())
        
        # construct count_retx result
        if not total_count:
            count_result = "0\t" * len(retxStatsMap[retxType.lower()])
        else:
            for k, v in sorted(retxStatsMap[retxType.lower()].items()):
                count_ratio = v / total_count
                stateRatio = 0
                if totalStatsMap[retxType.lower()][k]:
                    stateRatio = v / totalStatsMap[retxType.lower()][k]                
                count_result += str(count_ratio) + "\t"
                tot_result += str(total_count) + "\t"
                per_state_ratio += str(stateRatio) + "\t"
                per_state_count += str(v) + "\t"

        # construct rtt_retx result
        if not total_rtt:
            rtt_result = "0\t" * len(retxRTTMap[retxType.lower()])
        else:
            for k, v in sorted(retxRTTMap[retxType.lower()].items()):
                rtt_ratio = v / total_rtt
                rtt_per_state_ratio = 0
                if totalRTTMap[retxType.lower()][k]:
                   rtt_per_state_ratio = v / totalRTTMap[retxType.lower()][k]
                rtt_result += str(rtt_ratio) + "\t"
                rtt_tot_result += str(total_rtt) + "\t"
                rtt_per_state_ratio_result += str(rtt_per_state_ratio) + "\t"
                rtt_per_state_result += str(v) + "\t"

    else:
        print >> sys.stderr, "ERROR: Invalid retransmission type"
        return
    print "Retx Count Ratio for %s:" % retxType
    print count_result
    print "RTT Ratio %s:" %     retxType
    print rtt_result
    if DEBUG:
        print "Retx_Count: Total_count is %d" % total_count
        print "Retx_Count: Per State count is %s" % per_state_count
        print "Retx_Count: Per state ratio is %s" % per_state_ratio
        print "Retx_RTT: Total RTT is %d" % total_rtt
        print "Retx_RTT: Per State RTT is %s" % rtt_per_state_result
        print "Retx_RTT: Per State ratio is %s" % rtt_per_state_ratio_result
        print "*"*40

# RLC retransmission count vs signal strength
def rlcRetxCountVSSignalStrength(rlcCountMap):
    # TODO: Print Timeseries vs. retx count vs. avg signal strength.
    for i in rlcCountMap:
        pass

# Print map between retx count and signal strength
def printRLCRetxCountAndRSCP(rlcCountMap):
    for ts, snEntries in sorted(rlcCountMap.items()):
        for sn, detail in sorted(snEntries.items()):
            # exclude the first original RLC
            for i in range(1,len(detail[2])):
                # Retx count, RSCP, RRC state
                print "%d\t%f\t%d" % (i, util.meanValue(detail[2][i].sig["RSCP"]), detail[2][i].rrcID)

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
#################### Cross Layer Related ##############################
#######################################################################
# Print the best selection between TCP and UDP mapping 
# format: timestamp  tcp_byte   RLC_byte    RRC_state   (optional: dup_ack_num)
def printRetxIntervalWithMaxMap(QCATEntries, entryIndexMap, combMap, map_key = "ts_count"):
    maxIndex = clw.findBestMappedIndex(combMap[map_key]["RLC"], combMap[map_key]["TCP"], combMap["ts_entry"]["RLC"], combMap["sn_count"]["RLC"])
    if maxIndex == -1:
        print >> sys.stderr, "No retx happen"
        return

    # find the ratio for the promotion retransmission
    firstKey = sorted(combMap["ts_entry"]["TCP"][maxIndex].keys())[0]
    lastKey = sorted(combMap["ts_entry"]["RLC"][maxIndex].keys())[-1]
    beginIndex = entryIndexMap[combMap["ts_entry"]["TCP"][maxIndex][firstKey]]
    endIndex = entryIndexMap[combMap["ts_entry"]["RLC"][maxIndex][lastKey]]

    ############ Debug #############
    if DEBUG:
        print "Corresponding RLC count map:"
        print combMap["sn_count"]["RLC"][maxIndex]
        print "Retx TCP entries:" 
        for k, v in sorted(combMap["ts_entry"]["TCP"][maxIndex].items()):
            printTCPEntry(v)
        
        countTotalFACHPromote = 0.0
        countRetxFACHPromote = 0.0
        print "being index is %d" % beginIndex
        print "end index is %d" % endIndex
        for index in range(beginIndex, endIndex+1):
            if QCATEntries[index].rrcID == const.FACH_TO_DCH_ID:
                countTotalFACHPromote += len(QCATEntries[index].ul_pdu[0]["sn"] + QCATEntries[index].dl_pdu[0]["sn"])
                for pdu in QCATEntries[index].ul_pdu[0]["sn"] + QCATEntries[index].dl_pdu[0]["sn"]:
                    if combMap["sn_count"]["RLC"][maxIndex].has_key(pdu) and combMap["sn_count"]["RLC"][maxIndex][pdu] > 1:
                        countRetxFACHPromote += 1
        print "Total Fach promote %d" % countTotalFACHPromote
        print "Fach retx is %d" % countRetxFACHPromote
        ratio = 0
        if countTotalFACHPromote != 0:
            ratio = countRetxFACHPromote/countTotalFACHPromote
        print "The FACH promote retx ratio is %f" % (ratio)
        print "The retx dist is "
        print combMap["sn_retx_time_dist"]["RLC"][maxIndex]
        print "The average retx is %f" % (util.meanValue([util.meanValue([util.meanValue(j) for j in i.values()]) for i in combMap["sn_retx_time_dist"]["RLC"]]))
    
    # Use the relative difference in milliseconds
    tcpSortedItems = sorted(combMap[map_key]["TCP"][maxIndex].items())
    firstTCP = tcpSortedItems[0][0]
    for ts, v in tcpSortedItems:
        # Timestamp, tcp_info, rlc_info, 
        # TODO: change this if necessary
        print "%d\t%d\t%d\t%d\t%d" % ((int)((ts - firstTCP)*1000), 3, 0, max(combMap["sn_count"]["RLC"][maxIndex].values()), combMap["ts_entry"]["TCP"][maxIndex][ts].rrcID)
    for ts, v in sorted(combMap[map_key]["RLC"][maxIndex].items()):
        print "%d\t%d\t%d\t%d\t%d" % ((int)((ts - firstTCP)*1000), 0, 2, max(combMap["sn_count"]["RLC"][maxIndex].values()), combMap["ts_entry"]["RLC"][maxIndex][ts].rrcID)

    ###################### Dup ACK part #################
    # find the duplicate ack in between the first and last item
    dupACKMap = clw.detectDupACK(QCATEntries, beginIndex, endIndex)
    for key in dupACKMap:
        for index in dupACKMap[key]:
            ts = QCATEntries[index].timestamp
            print "%d\t%d\t%d\t%d\t%d\t%d" % ((int)((ts - firstTCP)*1000), 1, 1, max(combMap["sn_count"]["RLC"][maxIndex].values()), QCATEntries[index].rrcID, key)

# Print all the retransmission one-to-all mapping
def printAllRetxIntervalMap(QCATEntries, entryIndexMap, combMap, map_key = "ts_count"):
    for index in range(len(combMap[map_key]["TCP"])):
        # print TCP information
        firstKey = sorted(combMap["ts_entry"]["TCP"][index].keys())[0]
        print "First IP is:"
        printEntry(combMap["ts_entry"]["TCP"][index][firstKey])
        firstTCP = sorted(combMap[map_key]["TCP"][index].keys())[0]
        for ts, v in sorted(combMap["ts_entry"]["TCP"][index].items()): 
           print "%d\t%d\t%d\t%d\t%d" % ((int)((ts - firstTCP)*1000), 3, 0, max(combMap["sn_count"]["RLC"][index].values()), combMap["ts_entry"]["TCP"][index][ts].rrcID)
        for ts, v in sorted(combMap[map_key]["RLC"][index].items()):
            print "%d\t%d\t%d\t%d\t%d" % ((int)((ts - firstTCP)*1000), 0, 2, max(combMap["sn_count"]["RLC"][index].values()), combMap["ts_entry"]["RLC"][index][ts].rrcID) 


#######################################################################
#################### RLC Fast Retx Related ############################
#######################################################################
# plot the detailed case of RLC fast retransmission break down
# the duplicate ACKs and duplicate ACKs 
# @print "time_stamp \t sn_for_dup_ack \t sn_for_rlc"
def print_rlc_fast_retx_case (QCATEntries, rlc_fast_retx_map):
    offset = QCATEntries[rlc_fast_retx_map["dup_ack"][0]].timestamp * 1000
    for dup_ack_index in rlc_fast_retx_map["dup_ack"]:
        cur_entry = QCATEntries[dup_ack_index]
        print "%f\t%f\t%f" % (cur_entry.timestamp * 1000 - offset, cur_entry.dl_ctrl["ack"], 0)
    time_diff = 0
    for rlc_index in range(len(rlc_fast_retx_map["rlc"])-1):
        cur_entry = QCATEntries[rlc_fast_retx_map["rlc"][rlc_index]]
        length = len(cur_entry.ul_pdu[0]["sn"])
        if length:
            time_unit = (QCATEntries[rlc_fast_retx_map["rlc"][rlc_index+1]].timestamp - cur_entry.timestamp) * 1000.0 / float(length)
        for i in range(length):
            cur_time = cur_entry.timestamp*1000 + time_unit * i - offset
            print "%f\t%f\t%f" % (cur_time, 0, cur_entry.ul_pdu[0]["sn"][i])
    # print last rlc
    cur_entry = QCATEntries[rlc_fast_retx_map["rlc"][len(rlc_fast_retx_map["rlc"])-1]]
    for i in range(len(cur_entry.ul_pdu[0]["sn"])):
        cur_time = cur_entry.timestamp*1000 + time_unit * i - offset
        print "%f\t%f\t%f" % (cur_time, 0, cur_entry.ul_pdu[0]["sn"][i])

# print RLC fast retx benefit/cost detail
def print_rlc_fast_retx_cost_benefit(QCATEntries, retx_map, trans_time_benefit_cost_map, rtt_benefit_cost_time_map, rtt_benefit_cost_count_map, total_rtt, total_benefit_cost_rtt_map, total_count, total_benefit_cost_count_map):
    # rtt_benefit_cost_time indicate for per round trip
    win = float(len(retx_map["win"]))
    draw = float(len(retx_map["draw"]))
    draw_plus = float(len(retx_map["draw_plus"]))
    loss = float(len(retx_map["loss"]))
    totalCount = win + draw + draw_plus + loss
    win_ratio = draw_ratio = draw_plus_ratio = loss_ratio = 0
    if totalCount:
        win_ratio = win / totalCount
        draw_ratio = draw / totalCount
        draw_plus_ratio = draw_plus / totalCount
        loss_ratio = loss / totalCount
    print "Total Count is %d" % totalCount
    print "Win\tdraw_plus\tdraw\tloss"
    print "%f\t%f\t%f\t%f" % (win, draw_plus, draw, loss)
    print "%f\t%f\t%f\t%f" % (win_ratio, draw_plus_ratio, draw_ratio, loss_ratio)
    """
    # not useful since the avg only apply to each case alone
    print "*" * 30 + " Avg Transmission Delay Benefit/Cost:"
    print "Win Trans benefit time is %f" % util.meanValue(trans_time_benefit_cost_map["win"])
    print "Draw Trans Plus benefit time is %f" % util.meanValue(trans_time_benefit_cost_map["draw_plus"])
    print "Draw Trans overhead is %f" % util.meanValue(trans_time_benefit_cost_map["draw"])
    print "Loss Trans overhead is %f" % util.meanValue(trans_time_benefit_cost_map["loss"])
    print "*" * 30 + " Avg RTT Benefit/Cost:"
    print "Win avg RTT benefit time is %f" % util.meanValue(rtt_benefit_cost_time_map["win"])
    print "Draw Plus avg RTT benefit time is %f" % util.meanValue(rtt_benefit_cost_time_map["draw_plus"])
    print "Draw avg RTT overhead is %f" % util.meanValue(rtt_benefit_cost_time_map["draw"])
    print "Loss avg RTT overhead is %f" % util.meanValue(rtt_benefit_cost_time_map["loss"])
    print "*" * 30 + " Avg Count Benefit/Cost:"
    print "Win benefit count is %f" % util.meanValue(rtt_benefit_cost_count_map["win"])
    print "Draw Plus benefit count is %f" % util.meanValue(rtt_benefit_cost_count_map["draw_plus"])
    print "Draw overhead count is %f" % util.meanValue(rtt_benefit_cost_count_map["draw"])
    print "Loss overhead count is %f" % util.meanValue(rtt_benefit_cost_count_map["loss"])
    """

    # Avg RTT = total RTT diff per case / total count
    print "*" * 30 + " RTT improved time:"
    print "Win avg improved RTT: %f" % (total_benefit_cost_rtt_map["win"] / total_count)
    print "Draw Plus avg improved RTT: %f" % (total_benefit_cost_rtt_map["draw_plus"] / total_count)
    print "Draw avg cost RTT: %f" % (total_benefit_cost_rtt_map["draw"] / total_count)
    print "Loss avg cost RTT: %f" % (total_benefit_cost_rtt_map["loss"] / total_count)
    print "Orignal RTT: %f" % (total_rtt / total_count)

    # Count break down ratio = count_per_case / total count
    print "*" * 30 + " Count Ratio:"
    print "Win avg count percent: %f" % (total_benefit_cost_count_map["win"] / total_count)
    print "Draw Plus avg count percent: %f" % (total_benefit_cost_count_map["draw_plus"] / total_count)
    print "Draw avg count percent: %f" % (total_benefit_cost_count_map["draw"] / total_count)
    print "Loss avg count percent: %f" % (total_benefit_cost_count_map["loss"] / total_count)
    print "Total Count is %f" % total_count

    # Overall RTT benefit calculation
    print "*" * 30 + " Overall RTT ratio:"
    reduced_rtt = total_benefit_cost_rtt_map["win"] + total_benefit_cost_rtt_map["draw_plus"]
    incr_rtt = total_benefit_cost_rtt_map["loss"] + total_benefit_cost_rtt_map["draw"]
    correct_ratio = (reduced_rtt - incr_rtt) / total_rtt
    improved_ratio = reduced_rtt / total_rtt

    print "Correct Benefit RTT ratio: (%f - %f) / %f = \n>>>>>>>> %f" % (reduced_rtt, incr_rtt, total_rtt, correct_ratio)
    print "'Improved Benefit' RTT ratio: %f / %f = \n<<<<<<<< %f" % (reduced_rtt, total_rtt, improved_ratio)
    print "Win improved RTT ratio: %f " % (total_benefit_cost_rtt_map["win"] / total_rtt)
    print "Draw Plus improved RTT ratio: %f" % (total_benefit_cost_rtt_map["draw_plus"] / total_rtt)
    print "Draw overhead RTT ratio: %f" % (total_benefit_cost_rtt_map["draw"] / total_rtt)
    print "Loss overhead RTT ratio: %f" % (total_benefit_cost_rtt_map["loss"] / total_rtt)
    print "Total RTT is: %f" % total_rtt

    # Count overhead
    print "*" * 30 + " Count Overhead Ratio:"
    overhead_count = total_benefit_cost_count_map["draw"] + total_benefit_cost_count_map["loss"]
    print "Cost count (draw+loss) overhead ratio: %f / %f = \n!!!!!!! %f" % (overhead_count, total_count, overhead_count/total_count)

    """
    print "!"*50 + "Win" + "!"*50
    if win > 0:
        target_index = clw.findLongestRLCSeq(retx_map["win"])
        pw.print_rlc_fast_retx_case(QCATEntries, retx_map["win"][target_index])
    print "!"*50 + "Draw Plus" + "!"*50
    if draw_plus > 0:
        target_index = clw.findLongestRLCSeq(retx_map["draw_plus"])
        pw.print_rlc_fast_retx_case(QCATEntries, retx_map["draw_plus"][target_index])
    print "!"*50 + "Draw" + "!"*50
    if draw > 0:
        target_index = clw.findLongestRLCSeq(retx_map["draw"])
        pw.print_rlc_fast_retx_case(QCATEntries, retx_map["draw"][target_index])
    print "!"*50 + "Loss" + "!"*50
    if loss > 0:
        target_index = clw.findLongestRLCSeq(retx_map["loss"])
        pw.print_rlc_fast_retx_case(QCATEntries, retx_map["loss"][target_index])
    """

# print the fast retransmission statistics based on RRC state
def print_rlc_fast_retx_states_per_RRC_state(status_pdu_count_map):
    total_status_pdu = sum(status_pdu_count_map["total"].values())
    total_fast_retx = sum(status_pdu_count_map["dup_ack"].values())
    dup_ack_ratio_per_rrc_result = ""
    dup_ack_ratio_overall_result = ""
    
    
    for k, v in status_pdu_count_map["dup_ack"].items():
        if status_pdu_count_map["total"][k] == 0:
            cur_dup_ack_ratio_per_rrc = 0
        else:
            cur_dup_ack_ratio_per_rrc = status_pdu_count_map["dup_ack"][k] / status_pdu_count_map["total"][k] 
        dup_ack_ratio_per_rrc_result += str(cur_dup_ack_ratio_per_rrc) + "\t"
        dup_ack_ratio_overall_result += str(status_pdu_count_map["dup_ack"][k] / total_status_pdu) + "\t"

    print "*" * 30 + " RLC fast retx VS RRC:"
    print "RLC Fast Retx Ratio per state: %s" % dup_ack_ratio_per_rrc_result
    print "RLC Fast Retx Ratio overall: %s" % dup_ack_ratio_overall_result
    print status_pdu_count_map["total"]
    print status_pdu_count_map["dup_ack"]
    
# print the detail information about the win case
def print_real_win(rlc_fast_retx_map, real_win_count, tcp_received_num_case):
    real_win_ratio = 0
    total_win_sum = float(len(rlc_fast_retx_map["win"]))
    real_win_sum = sum(real_win_count.values())
    if total_win_sum:
        real_win_ratio = real_win_sum / total_win_sum
    print "Real win ratio is %f / %f = \n))))))) %f" % (real_win_sum, total_win_sum, real_win_ratio)
    count_result = ""
    for i in real_win_count.values():
        count_result += str(i) + "\t"
    count_result += str(tcp_received_num_case) + "\t"
    count_result += str(total_win_sum)
    print "True win detail: %s\n%s" % (str(real_win_count.keys())+ "\tTCP_received\tTotal", count_result)

#######################################################################
####################### Loss Analysis #################################
#######################################################################
# print the loss ratio based on retransmission
def print_loss_ratio(retxStatsMap, totCountStatsMap, retxRTTMap, totalRTTMap):
    printRetxRatio(retxStatsMap, totCountStatsMap, retxRTTMap, totalRTTMap, "rlc_ul")

#######################################################################
######################## Verification #################################
#######################################################################
# Verify the correctness of TCP and RLC one-to-all Mapping 
# Print all the TCP and mapped RLC packet details
def print_tcp_and_rlc_mapping_full_version(QCATEntries, entryIndexMap, pduID, srv_ip):
    for i in range(len(QCATEntries)):
        tcpEntry = QCATEntries[i]
        if tcpEntry.logID == const.PROTOCOL_ID and tcpEntry.ip["tlp_id"] == const.TCP_ID \
           and ((pduID == const.UL_PDU_ID and tcpEntry.ip["dst_ip"] == srv_ip) or \
                (pduID == const.DL_PDU_ID and tcpEntry.ip["src_ip"] == srv_ip)):
            if DEBUG:
                print "Before mapping"
                printTCPEntry(tcpEntry)
            
            mapped_RLCs, mapped_sn = clw.map_SDU_to_PDU(QCATEntries, i , pduID)
            print ("+" + "-"*15)*4
            print ">>> TCP Packet:"
            printTCPEntry(tcpEntry)
            if mapped_RLCs:
                print "<<< Mapped %d RLC PDUs:" % (len(mapped_RLCs))
                for rlcEntryTuple in mapped_RLCs:
                    if rlcEntryTuple[0].logID == const.UL_PDU_ID:
                        printRLCEntry(rlcEntryTuple[0], "up")
                    else:
                        printRLCEntry(rlcEntryTuple[0], "down")
            else:
                print "??? Not found a mapped RLC entry. Double check!!!"

# Verify the correctness of TCP and RLC one-to-all Mapping in terms of sequence number
# Print TCP sequence number plus a line of mapped RLC sequence number 
def print_tcp_and_rlc_mapping_sn_version(QCATEntries, entryIndexMap, pduID, srv_ip):
    TCP_entry_count = 0.0
    Mapped_TCP_entry_count = 0.0

    for i in range(len(QCATEntries)):
        tcpEntry = QCATEntries[i]
        if tcpEntry.logID == const.PROTOCOL_ID and tcpEntry.ip["tlp_id"] == const.TCP_ID \
           and ((pduID== const.UL_PDU_ID and tcpEntry.ip["dst_ip"] == srv_ip) or \
                (pduID == const.DL_PDU_ID and tcpEntry.ip["src_ip"] == srv_ip)):
            
            TCP_entry_count += 1
            mapped_RLCs, mapped_sn = clw.map_SDU_to_PDU(QCATEntries, i , pduID)
            if mapped_RLCs:
                Mapped_TCP_entry_count += 1

            """
            print "TCP\t" + str(int(tcpEntry.tcp["seq_num"]))[:-1]
            if mapped_RLCs:
                print "RLC\t" + str(mapped_sn)[1:-1]
            else:
                print "??? Not found a mapped RLC entry. Double check!!!"
            """
    ratio = 0
    if TCP_entry_count > 0:
        ratio = Mapped_TCP_entry_count / TCP_entry_count
    print "Mapped ratio is %f / %f = %f" % (Mapped_TCP_entry_count, TCP_entry_count, ratio)

#######################################################################
######################## Packet Trace #################################
#######################################################################
# Print the most recent information about the packet trace
def printTraceInformation(entries, logID, start = None, end = None):
    for entry in entries:
        # TODO: improve efficiency
        if entry.rrcID and ((start and entry.timestamp > start) or (not start)) and\
           ((end and entry.timestamp < end) or (not end)):
            if entry.logID == logID == const.PROTOCOL_ID and entry.ip["total_len"] > 0:
                print "%f\t%f\t%d" % (entry.timestamp, entry.ip["total_len"], entry.rrcID)
            elif entry.logID == logID == const.UL_PDU_ID and util.meanValue(entry.ul_pdu[0]["size"]) > 0:
                print "%f\t%f\t%d" % (entry.timestamp, util.meanValue(entry.ul_pdu[0]["size"]), entry.rrcID)
            elif entry.logID == logID == const.DL_PDU_ID and util.meanValue(entry.dl_pdu[0]["size"]) > 0:
                print "%f\t%f\t%d" % (entry.timestamp, util.meanValue(entry.dl_pdu[0]["size"]), entry.rrcID)


#######################################################################
######################## Context Info #################################
#######################################################################
# signal strength information
# NOTICE: the retransmission number refer to the number of 
def printRSCP (entries, entryID):
    for i in entries:
        if i.rrcID and i.sig["RSCP"] and i.logID == entryID:
            ts = i.timestamp
            print "%f\t%f\t%d" % (ts, util.meanValue(i.sig["RSCP"]), i.rrcID )

# Print a timestamp based retx count map vs RSCP
def printRetxCountvsRSCPbasedOnTS(retxMap):
    for ts, detail in sorted(retxMap.items()):
        print "%f\t%d\t%f\t%f" % (ts, detail[0], detail[1], detail[2])

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
	print "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%d" % (util.convert_ts_in_human(entry.timestamp),\
	 					entry.ip["src_ip"], entry.ip["dst_ip"], hex(entry.tcp["seq_num"]), \
	 					hex(entry.tcp["ack_num"]), entry.ip["total_len"], entry.tcp["seg_size"], \
                        entry.custom_header, \
                        const.RRC_MAP[entry.rrcID], util.meanValue(entry.sig["RSCP"]))

# print a UDP entry information
def printUDPEntry(entry):
    print "%s\t%s\t%s\t%s\t%s\t%s" % (util.convert_ts_in_human(entry.timestamp), entry.ip["src_ip"], \
                                      entry.ip["dst_ip"], entry.udp["src_port"], entry.udp["dst_port"], \
                                      entry.udp["seg_size"])

# print a RLC entry information
def printRLCEntry(entry, dir_type):
    printEntry(entry)
    if dir_type.lower() == "up":
        print "RLC AM UL Detail: " + str(entry.ul_pdu[0])
    elif dir_type.lower() == "down":
        print "RLC AM DL Detail: " + str(entry.dl_pdu[0])
    elif dir_type.lower() == "down_ctrl":
        print "RLC DL Ctrl Detail and RRC: %s\t%s" % (str(entry.dl_ctrl), entry.rrcID)

# print a RLC STATUS PDU
def printSTATUSEntry(entry):
    print "%s\t%s" % (util.convert_ts_in_human(entry.timestamp), entry.dl_ctrl)

# print a general entry
def printEntry(entry):
    print "%s\t%s" % (util.convert_ts_in_human(entry.timestamp), const.RRC_MAP[entry.rrcID])
	 
