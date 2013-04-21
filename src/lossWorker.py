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

DEBUG = True

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
def UDP_loss_cross_analysis(QCATEntries, loss_index_list, logID):
    # Loss over cellular network if 
    # 1. exceeding max Retx count
    # 2. there is a reset PDU in between the mapped RLC list and the next control message
    udp_loss_in_cellular = {"reset": rw.initFullRRCMap(0.0), "max_retx": rw.initFullRRCMap(0.0)}
    udp_loss_in_internet = rw.initFullRRCMap(0.0)

    for loss_index in loss_index_list:
        cur_entry = QCATEntries[loss_index] 
        mapped_rlc_tuple_list, mapped_sn_list = clw.map_SDU_to_PDU(QCATEntries, loss_index, logID)
        
        if mapped_rlc_tuple_list and cur_entry.rrcID:
            first_mapped_rlc_index = mapped_rlc_tuple_list[0][1]
            last_mapped_rlc_index = mapped_rlc_tuple_list[-1][1]
            max_tx_config = cur_entry.ul_config["max_tx"]
            next_ack_index = clw.findNextCtrlMsg(QCATEntries, loss_index, ctrl_type = "ack", cur_seq = last_mapped_rlc_index)
            next_list_index = clw.findNextCtrlMsg(QCATEntries, loss_index, ctrl_type = "list", cur_seq = last_mapped_rlc_index)
            ctrl_index = min(next_ack_index, next_list_index)
            
            # check reset
            reset_index = clw.find_reset_ack(QCATEntries, last_mapped_rlc_index+1, ctrl_index)
            # check for exceeding retx count
            rlc_tx_map = find_SN_within_interval(QCATEntries, first_mapped_rlc_index+1, ctrl_index)
            max_tx_count_num = 0
            if rlc_tx_map:
                max_tx_count_num = max([len(i) for i in rlc_tx_map.values()])

            if reset_index:
                udp_loss_in_cellular["reset"][cur_entry.rrcID] += 1
                if DEBUG:
                    print "-------------- Detect Reset --------------"
            elif max_tx_config and max_tx_count_num >= max_tx_config):
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

                if DEBUG:
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

# TODO: calculate the average RTT over each state


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
        




    

