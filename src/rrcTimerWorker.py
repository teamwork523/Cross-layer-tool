#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   04/28/2013

Validate the inferred RRC Timer
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
############### Validate RRC Inference Timer ####################
#################################################################
# create a timer map for the inference timer
# TODO: use nearest IP packets to calculate the promotion timer
#
# @ return
#   1. A nested map, with usage map[FROM_RRC][TO_RRC] = QxDM_RRC_TIMER
#       (Map_A, Map_B)
#       Map_A is the RRC log to RRC log time difference
#       Map_B is the RRC log to nearest IP log time difference

def get_RRC_timer_map(QCATEntries, demote_accurate = False):
    # use two RRC log ID difference to measure the difference
    rrc_to_rrc_timer_map = rw.initFullRRCMap({}, const.RRC_ORIG_MAP)
    # use the RRC log ID to nearest IP packets as metric
    rrc_to_nearest_ip_timer_map = rw.initFullRRCMap({}, const.RRC_ORIG_MAP)
    # store the percentage of RRC_to_IP /  RRC_to_RRC
    percentage_map = rw.initFullRRCMap({}, const.RRC_ORIG_MAP)

    for k in rrc_to_rrc_timer_map:
        rrc_to_rrc_timer_map[k] = rw.initFullRRCMap([], const.RRC_ORIG_MAP)
        rrc_to_nearest_ip_timer_map[k] = rw.initFullRRCMap([], const.RRC_ORIG_MAP)
        percentage_map[k] = rw.initFullRRCMap([], const.RRC_ORIG_MAP)

    rrcID_domain = set(const.RRC_ORIG_MAP)

    # check for the previous index
    priv_rrc_entry_index = None
    for index in range(len(QCATEntries)):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.RRC_ID and cur_entry.rrcID in rrcID_domain:
            if priv_rrc_entry_index:
                priv_entry = QCATEntries[priv_rrc_entry_index]
                time_diff = cur_entry.timestamp - priv_entry.timestamp
                rrc_to_rrc_timer_map[priv_entry.rrcID][cur_entry.rrcID].append(time_diff)
                # Find the nearest IP log
                ip_log_index = find_nearest_ip_index(QCATEntries, index - 1, priv_rrc_entry_index + 1)

                # Assign RRC to IP timer map
                new_time_diff = time_diff
                if ip_log_index:
                    ip_log = QCATEntries[ip_log_index]
                    new_time_diff = cur_entry.timestamp - ip_log.timestamp
                rrc_to_nearest_ip_timer_map[priv_entry.rrcID][cur_entry.rrcID].append(new_time_diff)
                if time_diff:
                    percentage_map[priv_entry.rrcID][cur_entry.rrcID].append(new_time_diff/time_diff)
            priv_rrc_entry_index = index

    if DEBUG:
        print "FACH promote Timer:", len(rrc_to_rrc_timer_map[const.FACH_ID][const.DCH_ID])   
        print util.listToStr(util.quartileResult(rrc_to_rrc_timer_map[const.FACH_ID][const.DCH_ID]))
        print "PCH promote Timer:", len(rrc_to_rrc_timer_map[const.PCH_ID][const.FACH_ID])
        print util.listToStr(util.quartileResult(rrc_to_rrc_timer_map[const.PCH_ID][const.FACH_ID]))
        print "DCH demotion Timer:", len(rrc_to_rrc_timer_map[const.DCH_ID][const.FACH_ID])   
        print util.listToStr(util.quartileResult(rrc_to_rrc_timer_map[const.DCH_ID][const.FACH_ID]))
        print "FACH demotion Timer:", len(rrc_to_rrc_timer_map[const.FACH_ID][const.PCH_ID])
        print util.listToStr(util.quartileResult(rrc_to_rrc_timer_map[const.FACH_ID][const.PCH_ID]))

        print ">"*50
        print "IP FACH promote Timer:", len(rrc_to_nearest_ip_timer_map[const.FACH_ID][const.DCH_ID])   
        print util.listToStr(util.quartileResult(rrc_to_nearest_ip_timer_map[const.FACH_ID][const.DCH_ID]))
        print "IP PCH promote Timer:", len(rrc_to_nearest_ip_timer_map[const.PCH_ID][const.FACH_ID])
        print util.listToStr(util.quartileResult(rrc_to_nearest_ip_timer_map[const.PCH_ID][const.FACH_ID]))
        print "IP DCH demotion Timer:", len(rrc_to_nearest_ip_timer_map[const.DCH_ID][const.FACH_ID])   
        print util.listToStr(util.quartileResult(rrc_to_nearest_ip_timer_map[const.DCH_ID][const.FACH_ID]))
        print "IP FACH demotion Timer:", len(rrc_to_nearest_ip_timer_map[const.FACH_ID][const.PCH_ID])
        print util.listToStr(util.quartileResult(rrc_to_nearest_ip_timer_map[const.FACH_ID][const.PCH_ID]))

        print ">"*50
        print "Percentage FACH promote Timer:", len(percentage_map[const.FACH_ID][const.DCH_ID])   
        print util.listToStr(util.quartileResult(percentage_map[const.FACH_ID][const.DCH_ID]))
        print "Percentage PCH promote Timer:", len(percentage_map[const.PCH_ID][const.FACH_ID])
        print util.listToStr(util.quartileResult(percentage_map[const.PCH_ID][const.FACH_ID]))
        print "Percentage DCH demotion Timer:", len(percentage_map[const.DCH_ID][const.FACH_ID])   
        print util.listToStr(util.quartileResult(percentage_map[const.DCH_ID][const.FACH_ID]))
        print "Percentage FACH demotion Timer:", len(percentage_map[const.FACH_ID][const.PCH_ID])
        print util.listToStr(util.quartileResult(percentage_map[const.FACH_ID][const.PCH_ID]))

    return (rrc_to_rrc_timer_map, rrc_to_nearest_ip_timer_map)
    

#################################################################
################### Helper Function #############################
#################################################################
# return the nearest IP packet index within given index range
# check whether the start_index and end_index reverse to that the range got
# reversed as well
# Return:
#   1. The index of the 
def find_nearest_ip_index(QCATEntries, start_index, end_index):
    direction = 1
    if start_index > end_index:
        direction = -1
    for index in range(start_index, end_index+1, direction):
        cur_entry = QCATEntries[index]
        if cur_entry.logID == const.PROTOCOL_ID:
            return index
    return None




        
