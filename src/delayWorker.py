#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/17/2013
Functions related to delay, TCP RTT calculation
"""

import os, sys, re
import const
import QCATEntry as qe
import PrintWrapper as pw
import Util as util

#################################################################
##################### TCP RTT releated ##########################
#################################################################
# calculate the TCP RTT result



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

