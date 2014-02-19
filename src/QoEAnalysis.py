#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/18/2014

QoE application performance analysis
"""

import os, sys, re
import const
import crossLayerWorker as clw
from QoE import QoE
import rrcTimerWorker as rtw
import Util as util

DEBUG = False

#################################################################
######################### Facebook ##############################
#################################################################
# Facebook performance analysis
def facebook_analysis(entryList, qoeFile, client_ip, carrier=const.TMOBILE, \
                      network_type=const.WCDMA):
    # import the user level trace
    qoeEvent = QoE(qoeFile)

    # get the network event map
    netEventMap = qoeEvent.getNetworkEventMap()

    # get the timer map
    rrc_trans_timer_map = rtw.getCompleteRRCStateTransitionMap(entryList, network_type, carrier)

    if DEBUG:
        for ts in netEventMap:
            print str(ts * 1000) + const.DEL + netEventMap[ts][1].action + \
                  const.DEL + netEventMap[ts][1].event

    # Output the following event 
    header = "Action" + const.DEL + \
             "Event" + const.DEL + \
             "User_latency(s)" + const.DEL + \
             "Network_latency(s)" + const.DEL + \
             "Network_latency_ratio" + const.DEL + \
             "START_IP_TS" + const.DEL + \
             "END_IP_TS" + const.DEL

    rrc_state_of_interest = []

    if network_type == const.WCDMA:
        if carrier == const.TMOBILE:
            rrc_state_of_interest = [const.DCH_TO_FACH_ID, \
                                     const.FACH_TO_DCH_ID, \
                                     const.FACH_TO_PCH_ID, \
                                     const.PCH_TO_FACH_ID]
        elif carrier == const.ATT:
            rrc_state_of_interest = [const.DISCONNECTED_TO_DCH_ID, \
                                     const.DCH_TO_DISCONNECTED_ID]
    elif network_type == const.LTE:
        pass

    for rrc_state in rrc_state_of_interest:
        header += const.RRC_MAP[rrc_state] + "_DURATION" + const.DEL

    print header

    entryLen = len(entryList)
    # display the result
    for startTS in sorted(netEventMap.keys()):
        endTS = netEventMap[startTS][0]
        startEntry = netEventMap[startTS][1]
        line = startEntry.action + const.DEL + \
               startEntry.event + const.DEL

        # user latency
        user_latency = endTS - startTS
        line += str(user_latency) + const.DEL

        # network latency
        zoomIn_start_index = util.binary_search_smallest_greater_timestamp_entry_id( \
                                  startTS - const.QOE_TIME_OFFSET, \
                                  0, entryLen - 1, entryList)
        zoomIn_end_index = util.binary_search_largest_smaller_timestamp_entry_id( \
                                  endTS + const.QOE_TIME_OFFSET, \
                                  0, entryLen - 1, entryList)
        zoomIn_first_ip, first_ip_index = util.find_nearest_ip(entryList, zoomIn_start_index, True, \
                                               src_ip = client_ip)
        zoomIn_last_ip, last_ip_index = util.find_nearest_ip(entryList, zoomIn_end_index, False, \
                                               dst_ip = client_ip)
        network_latency = 0.0
        if zoomIn_first_ip != None and \
           zoomIn_last_ip != None and \
           zoomIn_last_ip.timestamp > zoomIn_first_ip.timestamp:
            network_latency = zoomIn_last_ip.timestamp - zoomIn_first_ip.timestamp

        line += str(network_latency) + const.DEL
        # network latency ratio
        #line += str(min(1.0, network_latency / user_latency)) + const.DEL
        line += str(network_latency / user_latency) + const.DEL

        # IP timestamp
        if zoomIn_first_ip:
            line += util.convert_ts_in_human(zoomIn_first_ip.timestamp) + const.DEL
        else:
            line += "N/A" + const.DEL

        if zoomIn_last_ip:
            line += util.convert_ts_in_human(zoomIn_last_ip.timestamp) + const.DEL
        else:
            line += "N/A" + const.DEL

        # check whether RRC state transition occur
        for rrc_state in rrc_state_of_interest:
            rrc_timer = util.find_overlapped_transition_period(startTS, \
                                                               endTS, \
                                                               rrc_trans_timer_map, \
                                                               rrc_state, \
                                                               mode="both")
            line += str(rrc_timer) + const.DEL

        print line
        


