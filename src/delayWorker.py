#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/17/2013

Functions related to delay, TCP RTT calculation
"""

import os, sys, re
import const
import crossLayerWorker as clw
import QCATEntry as qe
import PrintWrapper as pw
import Util as util

RLC_RTT_DEBUG = False
TCP_RTT_DEBUG = False

#################################################################
##################### TCP RTT releated ##########################
#################################################################
# Calculate the TCP RTT for all TCP packet
# Time(Sender) - Time(ACK = Sender's seq + TCP payload size)
def calc_tcp_rtt(Entries, client_ip):
    entryLen = len(Entries)

    for i in range(entryLen):
        curEntry = Entries[i]
        if curEntry.logID == const.PROTOCOL_ID and \
           curEntry.ip["tlp_id"] == const.TCP_ID and \
           (curEntry.ip["total_len"] != curEntry.ip["header_len"] + curEntry.tcp["header_len"]):
            if curEntry.ip["src_ip"] == client_ip:
                tcp_len = curEntry.ip["total_len"] - curEntry.ip["header_len"] - curEntry.tcp["header_len"]
                ack_entry = find_tcp_ack_entry(Entries[i+1:], curEntry.ip["dst_ip"], "up",\
                            curEntry.tcp["seq_num"] + tcp_len)
                if ack_entry:
                    curEntry.rtt["tcp"] = ack_entry.timestamp - curEntry.timestamp
                    
                    if TCP_RTT_DEBUG:
                        print "Found one in uplink: " + str(curEntry.timestamp) + "\t" + str(curEntry.rtt["tcp"])
            elif curEntry.ip["dst_ip"] == client_ip:
                tcp_len = curEntry.ip["total_len"] - curEntry.ip["header_len"] - curEntry.tcp["header_len"]
                ack_entry = find_tcp_ack_entry(Entries[i+1:], curEntry.ip["src_ip"], "down",\
                            curEntry.tcp["seq_num"] + tcp_len)
                if ack_entry:
                    curEntry.rtt["tcp"] = ack_entry.timestamp - curEntry.timestamp

                if TCP_RTT_DEBUG:
                        print "Found one in downlink: " + str(curEntry.timestamp) + "\t" + str(curEntry.rtt["tcp"])


#################################################################
##################### RLC RTT releated ##########################
#################################################################
# calculate the RTT based on polling and STATUS PDU
# assume RTT doesn't varies within a certain amount of time
def calc_rlc_rtt(QCATEntries):
    recent_poll_index = None
    for index in range(len(QCATEntries)):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.UL_PDU_ID and check_polling_bit(cur_entry.ul_pdu[0]["header"]):
            recent_poll_index = index
        elif cur_entry.dl_ctrl["chan"]:
            if recent_poll_index: 
                # find an STATUS with a matched privious polling request
                rlc_rtt = cur_entry.timestamp - QCATEntries[recent_poll_index].timestamp
                # enforce the non-difference RTT
                if rlc_rtt > 0:
                    QCATEntries[recent_poll_index].rtt["rlc"] = rlc_rtt
                    if RLC_RTT_DEBUG:
                        print "RLC RTT: %f" % QCATEntries[recent_poll_index].rtt["rlc"]
            recent_poll_index = None


# assign the RLC RTT result
def assign_rlc_rtt(QCATEntries):
    recent_rtt = None
    for entry in QCATEntries:
        if entry.rtt["rlc"]:
            recent_rtt = entry.rtt["rlc"]
        elif recent_rtt:
            # TODO: downlink part is not well taken care
            if entry.logID == const.UL_PDU_ID or \
               entry.logID == const.DL_CTRL_PDU_ID or \
               entry.logID == const.DL_PDU_ID:
                entry.rtt["rlc"] = recent_rtt
        """
        if RLC_RTT_DEBUG:
            if entry.rtt["rlc"]:
                print "entry's RLC rtt is %f" % entry.rtt["rlc"]
        """

#################################################################
##################### Packet delay Info #########################
#################################################################
# Determine delays of packets around 
# extracted the packet delay before or after FACH state if previous state is DCH 
# @Return: a map between 
def extractFACHStatePktDelayInfo(entries, direction):
    # first extract a RRC list
    # RRC list -- list of [state_id, entries_index]
    rrc_list = []
    # {ts:delay_time}
    TCP_delay_map = {}
    RLC_delay_map = {}

    for i in range(len(entries)):
        if entries[i].logID == const.RRC_ID:
            rrc_list.append([entries[i].rrcID, i])
    
    count_DCH = 0
    count_FACH_interest = 0
    for rrc_index in range(1, len(rrc_list)-2):
        if rrc_list[rrc_index][0] == const.FACH_ID:
            if rrc_list[rrc_index-1][0] == const.DCH_ID and rrc_list[rrc_index+1][0] == const.DCH_ID:
                count_FACH_interest += 1
                # calculate the nearest pair
                (tcp_lead, tcp_lag) = findDelayPair(entries, rrc_list[rrc_index][1], const.PROTOCOL_ID)
                rlc_lead = rlc_lag = 0
                if direction.lower() == "up":
                    (rlc_lead, rlc_lag) = findDelayPair(entries, rrc_list[rrc_index][1], const.UL_PDU_ID)
                else:
                    (rlc_lead, rlc_lag) = findDelayPair(entries, rrc_list[rrc_index][1], const.DL_PDU_ID)
                
                # packet delay after state transition
                TCP_delay_map[entries[rrc_list[rrc_index][1]]] = tcp_lag
                RLC_delay_map[entries[rrc_list[rrc_index][1]]] = rlc_lag
        if rrc_list[rrc_index][0] == const.DCH_ID:
            count_DCH += 1
    
    """
    print "DCH: %d" % count_DCH
    print "FACH of interest: %d" % count_FACH_interest
    print "TCP diff avg & median: %f\t%f" % (util.meanValue(TCP_delay_map.values()), util.medianValue(TCP_delay_map.values()))
    print "RLC diff avg & median: %f\t%f" % (util.meanValue(RLC_delay_map.values()), util.medianValue(RLC_delay_map.values()))
    """
    # currently hardset delay limit to be 3s
    for i in TCP_delay_map.values():
        print i

#################################################################
################## First-hop RTT releated #######################
#################################################################
# Calculate the first hop latency proportion
#
# Input:
# 1. Entry list with TCP RTT calculated and estimated RLC RTT
# Output:
# 1. List of TCP RTT
# 2. Corresponding Average first hop latency (Overall transmission delay + OTA latency)
# 3. Transmission delay ratio
# 4. OTA delay ratio
def first_hop_latency_evaluation(entryList, pduID):
    tcp_rtt_list = []
    first_hop_rtt_list = []
    transmission_delay_ratio_rtt_list = []
    ota_delay_ratio_rtt_list = []
    entryLen = len(entryList)

    for i in range(entryLen):
        entry = entryList[i]
        if entry.rtt["tcp"] != None and entry.rtt["tcp"] > 0:
            # perform cross-layer mapping
            mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i , pduID)
            if mapped_RLCs:
                transmission_delay, rlc_rtt_list = calc_first_hop_latency(mapped_RLCs)
                tcp_rtt_list.append(entry.rtt["tcp"])
                first_hop_rtt_list.append(transmission_delay + util.meanValue(rlc_rtt_list))
                transmission_delay_ratio_rtt_list.append(min(transmission_delay / entry.rtt["tcp"], 1.0))
                ota_delay_ratio_rtt_list.append(min(util.meanValue(rlc_rtt_list) / entry.rtt["tcp"], 1.0))

    return (tcp_rtt_list, first_hop_rtt_list, transmission_delay_ratio_rtt_list, ota_delay_ratio_rtt_list)
                

#################################################################
################# helper function ###############################
#################################################################
# Return difference for nearest entries in both directions
def findDelayPair(entries, index, logType):
    beforeTime = 0
    afterTime = 0
    for i in range(index-1, 0, -1):
        if entries[i].logID == logType:
            beforeTime = entries[index].timestamp - entries[i].timestamp
            break

    for i in range(index+1, len(entries)):
        if entries[i].logID == logType:
            afterTime = entries[i].timestamp - entries[index].timestamp
            break

    return (beforeTime, afterTime)

# check if there is a polling request in the header list
def check_polling_bit(header_list):
    if header_list:
        for header in header_list:
            if header["p"]:
                return True
    return False

# find the ACK packet entry by given TCP ack number
def find_tcp_ack_entry(entryList, server_ip, direction, ack_num):
    # Define ACK packet as IP length = IP header length + TCP header length
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.TCP_ID and \
           (entry.ip["total_len"] == entry.ip["header_len"] + entry.tcp["header_len"]):
            # terminate search at a FIN packet
            if direction.lower() == "up":
                if entry.ip["src_ip"] == server_ip:
                    if entry.tcp["ack_num"] == ack_num:
                        return entry
                    elif entry.tcp["FIN_FLAG"]:
                        return None
            else:
                if entry.ip["dst_ip"] == server_ip:
                    if entry.tcp["ack_num"] == ack_num:
                        return entry
                    elif entry.tcp["FIN_FLAG"]:
                        return None
    return None

# Calculate the first-hop latency given a list of mapped RLC PDU list
# Output:
# 1. transmission delay
# 2. list of OTA RTT estimation
def calc_first_hop_latency(mapped_RLCs):
    transmission_delay = mapped_RLCs[-1][0].timestamp - mapped_RLCs[0][0].timestamp
    rlc_rtt_list = [rlc[0].rtt["rlc"] for rlc in mapped_RLCs if rlc[0].rtt["rlc"] != None]
    return transmission_delay, rlc_rtt_list
