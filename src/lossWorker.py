#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   04/14/2013

Loss Analysis on UDP trace 
"""

import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
import PrintWrapper as pw
import retxWorker as rw
import crossLayerWorker as clw
import PCAPParser as pp
import Util as util
from datetime import datetime

DEBUG = False
CUR_DEBUG = True
GAP_DEBUG = False
TIME_DEUBG = False

#################################################################
##################### UDP Loss Analysis #########################
#################################################################
# generate two the client lookup tables
#   1. uplink table
#   2. downlink table
# key: sequence number
# value: entry index
def get_UDP_clt_lookup_table (QCATEntries, direction, srv_ip, hash_target = "seq"):
    clt_ip_kw = "src_ip"
    srv_ip_kw = "dst_ip"
    if direction.lower() != "up":
        clt_ip_kw = "dst_ip"
        srv_ip_kw = "src_ip"
    
    # TODO: test why slow
    clt_uplink_lookup_table = {}
    clt_downlink_lookup_table = {}
    for entryIndex in range(len(QCATEntries)):
        cur_entry = QCATEntries[entryIndex]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID and \
           (cur_entry.ip[clt_ip_kw] == srv_ip or cur_entry.ip[srv_ip_kw] == srv_ip) and \
           cur_entry.rrcID:
            hash_key = None
            if hash_target == "seq":
                # hash the sequence number
                hash_key = cur_entry.udp["seq_num"]
            elif hash_target == "hash":
                # hash the payload
                udp_payload = clw.findEntireIPPacket(QCATEntries, entryIndex)
                udp_payload_len = cur_entry.udp["seg_size"]
                if not udp_payload_len:
                    udp_payload = []
                hash_key = util.md5_hash("".join(udp_payload[-udp_payload_len:]))
            if hash_key:
                if cur_entry.ip[srv_ip_kw] == srv_ip:
                    if clt_uplink_lookup_table.has_key(hash_key):
                        clt_uplink_lookup_table[hash_key].append(entryIndex)
                    else:
                        clt_uplink_lookup_table[hash_key] = [entryIndex]
                elif cur_entry.ip[clt_ip_kw] == srv_ip:
                    if clt_downlink_lookup_table.has_key(hash_key):
                        clt_downlink_lookup_table[hash_key].append(entryIndex)
                    else:
                        clt_downlink_lookup_table[hash_key] = [entryIndex]

    return (clt_uplink_lookup_table, clt_downlink_lookup_table)

# acquire server side UDP lookup table base on PCAP trace
def get_UDP_srv_lookup_table (pcap_filename, direction, hash_target, srv_ip = None):
    pcap = pp.PCAPParser(pcap_filename, direction, "udp")
    pcap.read_pcap()
    pcap.parse_pcap()
    # if server ip specified, then apply the filter
    if direction == "up":
        pcap.filter_based_on_cond("dst_ip", srv_ip)
    elif direction == "down":
        pcap.filter_based_on_cond("src_ip", srv_ip)
    pcap.build_udp_lookup_table(hash_target)
    
    return pcap.udp_lookup_table

# Calculate the UDP loss rate per RRC state statistics
# @ return
#   1. UDP loss per RRC state break down map
#   2. UDP total RRC state break down map
#   3. A list of UDP index that server didn't receive
#   4. A list of server keys that client didn't log
def UDP_loss_stats (QCATEntries, udp_clt_lookup_table, udp_srv_lookup_table, hash_target, srv_ip):
    # Statistic result
    udp_loss_per_rrc_map = rw.initFullRRCMap(0.0)
    udp_total_per_rrc_map = rw.initFullRRCMap(0.0)
    udp_srv_fail_recv_list = []  # list of UDP dropped over the internet
    udp_clt_fail_log_list = []

    # parse each UDP entry to check whether if appears on the server side table
    # use server ip to script the direction
    for hash_key, indexList in udp_clt_lookup_table.items():
        for entryIndex in indexList:
            cur_entry = QCATEntries[entryIndex]
            # count the src UDP packet
            udp_total_per_rrc_map[cur_entry.rrcID] += 1
            if not udp_srv_lookup_table.has_key(hash_key):
                udp_loss_per_rrc_map[cur_entry.rrcID] += 1
                udp_srv_fail_recv_list.append(entryIndex)

    # reverse map server side to the client side to check whether mis-log 
    for hash_key in udp_srv_lookup_table.keys():
        if not udp_clt_lookup_table.has_key(hash_key):
            udp_clt_fail_log_list.append(hash_key)

    return udp_loss_per_rrc_map, udp_total_per_rrc_map, udp_srv_fail_recv_list, udp_clt_fail_log_list

# UDP loss cross layer loss analysis
# determine whether packet lost over the internet or the cellular network
# return
# 1. udp loss in cellular network map
# 2. udp loss over internet map
def UDP_loss_cross_analysis(QCATEntries, loss_index_list, logID):
    # Loss over cellular network if 
    # 1. exceeding max Retx count
    # 2. there is a reset PDU in between the mapped RLC list and the next control message
    udp_loss_in_cellular = {"reset": rw.initFullRRCMap(0.0), "max_retx": rw.initFullRRCMap(0.0)}
    udp_loss_in_internet = rw.initFullRRCMap(0.0)

    entry_len = len(QCATEntries)
    max_retx_count_overall = 0.0

    for loss_index in loss_index_list:
        cur_entry = QCATEntries[loss_index] 
        mapped_rlc_tuple_list, mapped_sn_list = clw.map_SDU_to_PDU(QCATEntries, loss_index, logID)
        
        if mapped_rlc_tuple_list and cur_entry.rrcID:
            first_mapped_rlc_index = mapped_rlc_tuple_list[0][1]
            last_mapped_rlc_index = mapped_rlc_tuple_list[-1][1]
            first_mapped_rlc_sn = min(QCATEntries[first_mapped_rlc_index].ul_pdu[0]["sn"])
            last_mapped_rlc_sn = min(QCATEntries[last_mapped_rlc_index].ul_pdu[0]["sn"])
            
            max_tx_config = cur_entry.ul_config["max_tx"]
            next_ack_index = clw.findNextCtrlMsg(QCATEntries, loss_index, ctrl_type = "ack", cur_seq = last_mapped_rlc_sn)
            next_list_index = clw.findNextCtrlMsg(QCATEntries, loss_index, ctrl_type = "list", cur_seq = last_mapped_rlc_sn)
            
            ctrl_index = entry_len
            if next_ack_index:
                ctrl_index = min(next_ack_index, ctrl_index)
            if next_list_index:
                ctrl_index = min(next_list_index, ctrl_index)
            
            # check reset
            reset_index = clw.find_reset_ack(QCATEntries, last_mapped_rlc_index + 1, ctrl_index)
            # check for exceeding retx count
            rlc_tx_map = clw.find_SN_within_interval(QCATEntries, first_mapped_rlc_index + 1, ctrl_index)
            max_tx_count_num = 0
            if rlc_tx_map:
                max_tx_count_num = max([len(i) for i in rlc_tx_map.values()])
                if max_tx_count_num > max_retx_count_overall:
                    max_retx_count_overall = max_tx_count_num
            if reset_index:
                udp_loss_in_cellular["reset"][cur_entry.rrcID] += 1
                if DEBUG:
                    print "-------------- Detect Reset --------------"
            elif max_tx_config and max_tx_count_num >= max_tx_config:
                udp_loss_in_cellular["max_retx"][cur_entry.rrcID] += 1
                if DEBUG:
                    print "%%%%%%%%%%%% Max retx configued: " , max_tx_config
                    print "%%%%%%%%%%%% Cur retx configued: " , max_tx_count_num
            else:
                udp_loss_in_internet[cur_entry.rrcID] += 1
           
            """
            # print out retransmission over PCH promotion
            # investigate high PCH loss rate
            #if cur_entry.rrcID and cur_entry.rrcID == const.PCH_TO_FACH_ID:
            print "%"* 100
            print "%"* 40 + "Curious Case:" + "%"* 40
            pw.printUDPEntry(cur_entry)
            print "%"* 100
            print "%"* 100
            # find the lower bound of the range
            max_index = clw.find_nearest_status(QCATEntries, loss_index, max(mapped_sn_list))
            print "is max index correct %s" % (max_index > loss_index)
            target_sn_set = set(mapped_sn_list)
            dup_sn_map, rlc_tx_index_list = clw.loss_analysis_with_rlc_retx(QCATEntries, loss_index, max_index, target_sn_set)
            print "max # of retx is %d" % max([len(i) for i in dup_sn_map.values()])
            pw.print_loss_case(QCATEntries, loss_index, rlc_tx_index_list)
            """

    if CUR_DEBUG:
        print "Max RLC retx is ", max_retx_count_overall

    return udp_loss_in_cellular, udp_loss_in_internet

#################################################################
######################### UDP RTT ###############################
#################################################################            
# use both direction lookup table to assign RTT
# if UDP lost, then RTT is -1
def assign_udp_rtt(QCATEntries, direction, clt_uplink_table, clt_downlink_table):
    src_table = clt_uplink_table
    dst_table = clt_downlink_table
    if direction.lower() != "up":
        src_table = clt_downlink_table
        dst_table = clt_uplink_table
    
    for index_list in src_table.values():
        for index in index_list:
            cur_entry = QCATEntries[index]
            cur_seq_num = cur_entry.udp["seq_num"]
            # find the corresponding entry, and assign UDP RTT
            if cur_seq_num:
                if dst_table.has_key(cur_seq_num):
                    echo_index_list = dst_table[cur_seq_num]
                    for echo_index in echo_index_list:
                        cur_diff = QCATEntries[echo_index].timestamp - cur_entry.timestamp
                        if cur_diff > 0:
                            if not cur_entry.rtt["udp"] or cur_entry.rtt["udp"] > cur_diff:
                                cur_entry.rtt["udp"] = cur_diff
                else:
                    cur_entry.rtt["udp"] = -1.0
                if cur_entry.rtt["udp"] > const.UDP_RTT_LIMIT:
                    cur_entry.rtt["udp"] = -1.0
                if False:
                    print "UDP RTT is %f" % cur_entry.rtt["udp"]
                    pw.printUDPEntry(QCATEntries[echo_index])

    """
    for index in range(len(QCATEntries)):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID and \
           cur_entry.udp["seq_num"]:
            echo_src_ip = None
            echo_dst_ip = None
            if direction.lower() == "up":
                echo_src_ip = server_ip
            else:
                echo_dst_ip = server_ip
            echo_index = find_echo_udp_index (QCATEntries, index+1, cur_entry.udp["seq_num"], \
                                              echo_src_ip, echo_dst_ip)
            if echo_index:
                cur_entry.rtt["udp"] = QCATEntries[echo_index].timestamp - cur_entry.timestamp
                if DEBUG:
                    if cur_entry.rtt["udp"] > 3:
                        print "UDP RTT is : %f" % cur_entry.rtt["udp"]
                        pw.printUDPEntry(cur_entry)
     """

# calculate the average RTT over each state
def cal_UDP_RTT_per_state (QCATEntries, direction, clt_up_table, clt_down_table):
    udp_rtt_per_state = rw.initFullRRCMap(0.0)
    for k in udp_rtt_per_state:
        udp_rtt_per_state[k] = []

    lookup_table = clt_up_table
    if direction.lower() != "up":
        lookup_table = clt_down_table

    for index_list in lookup_table.values():
        for index in index_list:
            cur_entry = QCATEntries[index]
            if cur_entry.rrcID and cur_entry.rtt["udp"] and cur_entry.rtt["udp"] > 0:
                udp_rtt_per_state[cur_entry.rrcID].append(cur_entry.rtt["udp"])

    return udp_rtt_per_state    

#################################################################
##################### Gap Analysis Analysis #####################
#################################################################
# For every gap period, we want to know the RLC layer retransmission ratio
# @return
#   1. RRC Map structure:
#      {gap_period: {"retx":{FACH:[], PCH:[], DCH:[]}, "total":{}}, ...}
#   2. Retx ratio map:
#      {gap_period: [list of ratio], ...}
def rlc_retx_based_on_gap (QCATEntries, direction):
    index = 0
    entry_length = len(QCATEntries)
    gap_retx_per_rrc_map = {}
    gap_retx_list_map = {}
    tot_rlc_num = 0.0

    while index < entry_length:
        cur_entry = QCATEntries[index]
        cur_gap = cur_entry.udp["gap"]

        if cur_entry.ip["tlp_id"] == const.UDP_ID and cur_gap >= 0:
            # find the last gap_period message
            last_map_index = find_last_same_gap_entry_index(QCATEntries, index, cur_gap)
            if GAP_DEBUG:
                print "Current index is %d" % index
                print "Last map index is %d" % last_map_index
            # map the current UDP packet to the RLC layer PDUs
            first_rlc_list, first_sn_list = clw.map_SDU_to_PDU(QCATEntries, index, const.UL_PDU_ID)
            last_rlc_list, last_sn_list = clw.map_SDU_to_PDU(QCATEntries, last_map_index, const.UL_PDU_ID)
            # get the corresponding RLC log message
            if first_rlc_list and last_rlc_list and last_sn_list:
                rlc_begin_index = first_rlc_list[0][1]
                tmp_rlc_end_index = last_rlc_list[-1][1]
                rlc_end_index = clw.find_nearest_status(QCATEntries, tmp_rlc_end_index, max(last_sn_list))
                if GAP_DEBUG:
                    print "First RLC mapped index is ", rlc_begin_index
                    print "Last RLC mapped index is ", rlc_end_index

                if rlc_begin_index < rlc_end_index:
                    total_count_map, retx_count_map, retx_num, total_num = find_retx_within_a_range(QCATEntries, rlc_begin_index, rlc_end_index, direction)
                    """
                    if GAP_DEBUG:
                        print "Cur_gap is %f" % cur_gap
                        print "retx_num is %f" % retx_num
                    """
                    tot_rlc_num += total_num
                    if gap_retx_list_map.has_key(cur_gap):
                        gap_retx_list_map[cur_gap].append(retx_num)
                    else:
                        gap_retx_list_map[cur_gap] = [retx_num]
                    if gap_retx_per_rrc_map.has_key(cur_gap):
                        gap_retx_per_rrc_map[cur_gap]["retx"] = util.merge_two_dict(gap_retx_per_rrc_map[cur_gap]["retx"], retx_count_map)
                        gap_retx_per_rrc_map[cur_gap]["total"] = util.merge_two_dict(gap_retx_per_rrc_map[cur_gap]["total"], total_count_map)
                    else:
                        gap_retx_per_rrc_map[cur_gap] = {"retx": retx_count_map, "total": total_count_map}
                                                                                                                                                                                                                                                                                                                             
            index = last_map_index

        index += 1

    # recalculate the whole group by the ratio of dividing the total group number
    for gap, retx_list in gap_retx_list_map.items():
        gap_retx_list_map[gap] = [i/tot_rlc_num for i in retx_list]

    # display the retransmission result
    if True:
        #print "Ready to show results ...."
        for k in sorted(gap_retx_list_map.keys()):
            mean, stdev = util.meanStdevPair(gap_retx_list_map[k], upper_bound = 300.0)
            print "%f\t%f\t%f" % (k, mean, stdev / 10.0)
            #print "%f\t%s" % (k, util.listToStr(util.quartileResult(gap_retx_list_map[k])))
            #print "%f\t%s" % (k, gap_retx_list_map[k])

    return gap_retx_per_rrc_map, gap_retx_list_map

# Derive the RTT value for each gap period
# @return
#   1. Map between gap result and RTT value
def get_gap_to_rtt_map(QCATEntries):
    gap_rtt_per_rrc_map = {}
    gap_rtt_list_map = {}
    index = 0
    entry_length = len(QCATEntries)

    while index < entry_length:
        cur_entry = QCATEntries[index]
        cur_gap = cur_entry.udp["gap"]

        if cur_entry.ip["tlp_id"] == const.UDP_ID and cur_gap >= 0:
            # find the last gap_period message
            last_map_index = find_last_same_gap_entry_index(QCATEntries, index, cur_gap)
            
            # update the RTT map table
            for temp_index in range(index, last_map_index+1):
                temp_entry = QCATEntries[temp_index]
                cur_rtt = temp_entry.rtt["udp"]
                cur_rrc = temp_entry.rrcID
                # append to RTT list
                if cur_rtt:
                    if gap_rtt_list_map.has_key(cur_gap):
                        gap_rtt_list_map[cur_gap].append(cur_rtt)
                    else:
                        gap_rtt_list_map[cur_gap] = [cur_rtt]
                # update RRC map
                if cur_rrc:
                    if not gap_rtt_per_rrc_map.has_key(cur_gap):
                        gap_rtt_per_rrc_map[cur_gap] = rw.initFullRRCMap([])
                    gap_rtt_per_rrc_map[cur_gap][cur_rrc].append(cur_rtt)
            # leap the index
            index = last_map_index
        # update the index
        index += 1

    # display all the RTT timer
    if True:
        for k in sorted(gap_rtt_list_map.keys()):
            mean, stdev = util.meanStdevPair(gap_rtt_list_map[k])
            print "%f\t%f\t%f" % (k, mean, stdev)

    return gap_rtt_list_map, gap_rtt_per_rrc_map

#################################################################
######################### Helper function #######################
#################################################################
# find the echo UDP packet by sequence number and ip address
def find_echo_udp_index (QCATEntries, startIndex, seq_num, src_ip = None, dst_ip = None):
    entry_len = len(QCATEntries)
    for index in range(startIndex, entry_len):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID:
            if cur_entry.udp["seq_num"] == seq_num:
                if src_ip and cur_entry.ip["src_ip"] == src_ip:
                    return index
                if dst_ip and cur_entry.ip["dst_ip"] == dst_ip:
                    return index
    return None

# find the last gap result in all the entries
def find_last_same_gap_entry_index(QCATEntries, startIndex, target_gap):
    # only search for UDP packet
    entry_len = len(QCATEntries)
    priv_same_gap_index = startIndex

    for index in range(startIndex+1, entry_len):
        cur_entry = QCATEntries[index]
        if cur_entry.ip["tlp_id"] == const.UDP_ID:
            """
            if CUR_DEBUG:
                print cur_entry.udp["gap"]
            """            
            if cur_entry.udp["gap"] == target_gap:
                priv_same_gap_index = index
            else:
                break

    return priv_same_gap_index

# Assume the RLC retransmission analysis is done
# Find the RLC retransmission within a given range
# @return
#   1. A map between the RRC state and total RLC num
#   2. A map between the RRC state and retx RLC num
#   3. Retransmission Ratio
def find_retx_within_a_range(QCATEntries, startIndex, endIndex, direction):
    tot_rlc_count = rw.initFullRRCMap(0.0)
    retx_rlc_count = rw.initFullRRCMap(0.0)
    # method 2
    exist_sn_set = set([])
    for index in range(startIndex, endIndex+1):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.UL_PDU_ID or \
           cur_entry.logID == const.DL_PDU_ID:
            cur_rrcID = cur_entry.rrcID
            cur_rlc_pdus = cur_entry.ul_pdu[0]
            if direction.lower() == "down":
                cur_rlc_pdus = cur_entry.dl_pdu[0]
            
            if cur_rrcID:
                # check current sequence number
                for sn in cur_rlc_pdus["sn"]:
                    if sn in exist_sn_set:
                        retx_rlc_count[cur_rrcID] += 1
                    else:
                        exist_sn_set.add(sn)
                    tot_rlc_count[cur_rrcID] += 1

    ratio = 0.0
    total_sum = float(sum(tot_rlc_count.values()))
    retx_sum = float(sum(retx_rlc_count.values()))
    if total_sum > 0.0:
        # ratio = retx_sum / total_sum
        ratio = retx_sum
    
    return tot_rlc_count, retx_rlc_count, retx_sum, total_sum



