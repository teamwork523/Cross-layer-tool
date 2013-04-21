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
# generate the client lookup table based on QxDM trace
# key: sequence number
# value: entry index
def get_UDP_clt_lookup_table (QCATEntries, direction, srv_ip, dst_iphash_target = "seq"):
    ip_kw = "dst_ip"
    if direction.lower() != "up":
        ip_kw = "src_ip"
        
    clt_lookup_table = {}
    for entryIndex in range(len(QCATEntries)):
        cur_entry = QCATEntries[entryIndex]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID and \
           cur_entry.ip[ip_kw] == srv_ip and \
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
                if clt_lookup_table.has_key(hash_key):
                    clt_lookup_table[hash_key].append(entryIndex)
                else:
                    clt_lookup_table[hash_key] = [entryIndex]

    return clt_lookup_table

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
def UDP_loss_cross_analysis(QCATEntries, loss_index_list, logID):
    for loss_index in loss_index_list:
        cur_entry = QCATEntries[loss_index] 
        mapped_rlc_tuple_list, mapped_sn_list = clw.map_SDU_to_PDU(QCATEntries, loss_index, logID)
        if mapped_rlc_tuple_list:
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
            dup_sn_map, rlc_retx_index_list = clw.loss_analysis_with_rlc_retx(QCATEntries, loss_index, max_index, target_sn_set)
            print "max # of retx is %d" % max([len(i) for i in dup_sn_map.values()])
            pw.print_loss_case(QCATEntries, loss_index, rlc_retx_index_list)
                
#################################################################
######################### UDP RTT ###############################
#################################################################            
# assign UDP rtt over
def assign_udp_rtt(QCATEntries, direction, server_ip): 
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

# TODO: calculate the average RTT over each state


#################################################################
######################### Helper function #######################
#################################################################
# find the echo UDP packet by sequence number and ip address
def find_echo_udp_index (QCATEntries, startIndex, seq_num, src_ip = None, dst_ip = None):
    for index in range(startIndex, len(QCATEntries)):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID:
            if cur_entry.udp["seq_num"] == seq_num:
                if src_ip and cur_entry.ip["src_ip"] == src_ip:
                    return index
                if dst_ip and cur_entry.ip["dst_ip"] == dst_ip:
                    return index
    return None
        




    

