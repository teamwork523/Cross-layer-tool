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

#################################################################
##################### UDP Loss Analysis #########################
#################################################################
# acquire the UDP lookup table 
def get_UDP_lookup_table (pcap_filename, direction, srv_ip = None):
    pcap = pp.PCAPParser(pcap_filename, direction, "udp")
    pcap.read_pcap()
    pcap.parse_pcap()
    # if server ip specified, then apply the filter
    if srv_ip:
        pcap.filter_based_on_cond("srv_ip", srv_ip)
    pcap.build_udp_lookup_table()
    
    return pcap.udp_lookup_table

# Calculate the UDP loss rate per RRC state
# @ return
#   1. UDP loss per RRC state break down map
#   2. UDP total RRC state break down map
#   3. A list of UDP loss index
def UDP_loss_analysis (QCATEntries, udp_lookup_table, srv_ip):
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
            udp_payload_key = util.md5_hash("".join(udp_payload[-udp_payload_len:]))
            if cur_entry.ip["dst_ip"] == srv_ip and not udp_lookup_table.has_key(udp_payload_key):
                udp_loss_per_rrc_map[cur_entry.rrcID] += 1
                udp_loss_list.append(entryIndex)

    return udp_loss_per_rrc_map, udp_total_per_rrc_map, udp_loss_list

                  
            
    





    

