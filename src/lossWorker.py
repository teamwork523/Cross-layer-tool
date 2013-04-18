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
# acquire the UDP lookup table 
def get_UDP_lookup_table (pcap_filename, direction, hash_target, srv_ip = None):
    pcap = pp.PCAPParser(pcap_filename, direction, "udp")
    pcap.read_pcap()
    pcap.parse_pcap()
    # if server ip specified, then apply the filter
    if srv_ip:
        pcap.filter_based_on_cond("srv_ip", srv_ip)
    pcap.build_udp_lookup_table(hash_target)
    
    return pcap.udp_lookup_table

# Calculate the UDP loss rate per RRC state statistics
# @ return
#   1. UDP loss per RRC state break down map
#   2. UDP total RRC state break down map
#   3. A list of UDP loss index
def UDP_loss_stats (QCATEntries, udp_lookup_table, hash_target, srv_ip):
    # Statistic result
    udp_loss_per_rrc_map = rw.initFullRRCMap(0.0)
    udp_total_per_rrc_map = rw.initFullRRCMap(0.0)
    udp_loss_list = []

    # parse each UDP entry to check whether if appears on the server side table
    # use server ip to script the direction
    for entryIndex in range(len(QCATEntries)):
        cur_entry = QCATEntries[entryIndex]
        if cur_entry.logID == const.PROTOCOL_ID and \
           cur_entry.ip["tlp_id"] == const.UDP_ID and \
           cur_entry.rrcID:
            udp_payload = clw.findEntireIPPacket(QCATEntries, entryIndex)
            udp_payload_len = cur_entry.udp["seg_size"]
            if not udp_payload_len:
                udp_payload = []
            
            # count the UDP packet
            udp_total_per_rrc_map[cur_entry.rrcID] += 1
            # handle different hash types            
            udp_payload_key = None
            if hash_target == "hash":
                udp_payload_key = util.md5_hash("".join(udp_payload[-udp_payload_len:]))
            elif hash_target == "seq":
                udp_payload_key = cur_entry.udp["seq_num"]
            # TODO: handle diff hash target
            if cur_entry.ip["dst_ip"] == srv_ip and not udp_lookup_table.has_key(udp_payload_key):
                udp_loss_per_rrc_map[cur_entry.rrcID] += 1
                udp_loss_list.append(entryIndex)

    return udp_loss_per_rrc_map, udp_total_per_rrc_map, udp_loss_list

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
            echo_index = find_echo_udp_index (QCATEntries, index, cur_entry.udp["seq_num"], \
                                              echo_src_ip, echo_dst_ip)
            if echo_index:
                cur_entry.rtt["udp"] = QCATEntries[echo_index].timestamp - cur_entry.timestamp
                if DEBUG:
                    print "UDP RTT is : %f" % cur_entry.rtt["udp"]


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
        




    

