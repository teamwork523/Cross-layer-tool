#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/18/2014

Copyright (c) 2012-2014 RobustNet Research Group, University of Michigan.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by the RobustNet Research Group, University of Michigan.  The name of the
RobustNet Research Group, University of Michigan may not 
be used to endorse or promote products derived
from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

QoE application performance analysis
"""

import os, sys, re
import const
import crossLayerWorker as clw
import flowAnalysis as fa
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
    #netEventMap = qoeEvent.getActionTimerMap()
    
    # get the timer map
    rrc_trans_timer_map = rtw.getCompleteRRCStateTransitionMap(entryList, network_type, carrier)

    # get all the flows and flow time map
    #fa.parse_http_fields(entryList)
    flows = fa.extractTCPFlows(entryList)
    # filter out the black list for background traffic
    blackListURLs = ["b-api.facebook.com"]
    newflows = fa.filterOutBlackListDNSurls(flows, blackListURLs)
    flowTimerMap = fa.convertIntoFlowTimerMap(newflows)
    #sortedFlowStartTime = sorted(flowTimerMap.keys())

    if DEBUG:
        print "&"*80
        print "&"*80
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
             "END_IP_TS" + const.DEL + \
             "RRC_Type" + const.DEL + \
             "Diff_whole_action_vs_SF"

    #print header

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

        # network latency using flow analysis
        #flowStartTS = util.binary_search_largest_smaller_value(startTS - const.QOE_TIME_OFFSET, \
        #                                                       sortedFlowStartTime)
        (flow, ipList) = findCorrespondingIPPackets(entryList, startTS, endTS)
        network_latency = 0.0
        if ipList != None and len(ipList) > 1:
            network_latency = ipList[-1].timestamp - ipList[0].timestamp

        line += str(network_latency) + const.DEL
        # network latency ratio
        #line += str(min(1.0, network_latency / user_latency)) + const.DEL
        line += str(network_latency / user_latency) + const.DEL

        # IP timestamp
        if ipList != None and len(ipList) > 1:
            line += util.convert_ts_in_human(ipList[0].timestamp) + const.DEL + \
                    util.convert_ts_in_human(ipList[-1].timestamp) + const.DEL
        else:
            line += "N/A" + const.DEL + "N/A" + const.DEL

        # RRC state transition analysis
        if ipList != None and len(ipList) > 1:
            rrc_trans_state_bool_map = util.gen_RRC_trans_state_list_map(carrier, \
                                                                         network_type, \
                                                                         item="bool")
            for rrc_trans_state in rrc_trans_state_bool_map.keys():
                overlap_timer = util.find_overlapped_transition_period(ipList[0].timestamp, \
                                                                       ipList[-1].timestamp, \
                                                                       rrc_trans_timer_map, \
                                                                       rrc_trans_state, \
                                                                       mode="both")
                if overlap_timer > 0:
                    rrc_trans_state_bool_map[rrc_trans_state] = True

            if network_type == const.WCDMA:
                if carrier == const.TMOBILE:
                    if rrc_trans_state_bool_map[const.DCH_TO_FACH_ID] == True:
                        line += const.RRC_MAP[const.DCH_TO_FACH_ID] + const.DEL
                    elif rrc_trans_state_bool_map[const.PCH_TO_FACH_ID] == True and \
                         rrc_trans_state_bool_map[const.FACH_TO_DCH_ID] == True:
                        line += const.RRC_MAP[const.PCH_TO_FACH_ID] + "+" + \
                                const.RRC_MAP[const.FACH_TO_DCH_ID] + const.DEL
                    elif rrc_trans_state_bool_map[const.FACH_TO_DCH_ID] == True:
                        line += const.RRC_MAP[const.FACH_TO_DCH_ID] + const.DEL
                    else:
                        line += "Normal" + const.DEL
                elif carrier == const.ATT:
                    if rrc_trans_state_bool_map[const.DCH_TO_DISCONNECTED_ID] == True:
                        line += const.RRC_MAP[const.DCH_TO_DISCONNECTED_ID] + const.DEL
                    elif rrc_trans_state_bool_map[const.DISCONNECTED_TO_DCH_ID] == True:
                        line += const.RRC_MAP[const.DISCONNECTED_TO_DCH_ID] + const.DEL
                    else:
                        line += "Normal" + const.DEL
        else:
            line += "N/A" + const.DEL

        # append the difference between the whole action and the SF flag
        """
        if ipList != None and len(ipList) > 1:
            eventChainIndex = netEventMap[startTS][-1]
            eventChain = qoeEvent.actionMap[startEntry.action][eventChainIndex]
            (actionflow, actionIpList) = findCorrespondingIPPackets(entryList, \
                                         eventChain[0].timestamp, eventChain[-1].timestamp)
            if actionIpList != None and len(actionIpList) > 0:
                line += str(actionIpList[-1].timestamp - actionIpList[0].timestamp - \
                            network_latency) + const.DEL
            else:
                line += "0.0" + const.DEL
        """
        eventChainIndex = netEventMap[startTS][-1]
        eventChain = qoeEvent.actionMap[startEntry.action][eventChainIndex]
        line += util.convert_ts_in_human(eventChain[0].timestamp) + const.DEL + \
                util.convert_ts_in_human(startTS) + const.DEL + \
                util.convert_ts_in_human(endTS) + const.DEL
        if ipList != None and len(ipList) > 1:
            print line
        else:
            print >> sys.stderr, line


#################################################################
######################### Validation ############################
#################################################################
# Validate the QoE trace isolate the corresponding flows
def checkWhetherQoEMappingToLowerLayer(entryList, qoeFile, client_ip, \
                                       carrier=const.TMOBILE, \
                                       network_type=const.WCDMA):
    # import the user level trace
    qoeEvent = QoE(qoeFile)

    # get the action timer map with a offset value
    #timerMap = qoeEvent.getActionTimerMap(const.QOE_TIME_OFFSET)
    timerMap = qoeEvent.getNetworkEventMap(const.QOE_TIME_OFFSET)
    sortedTimerKey = sorted(timerMap.keys())
    lowerBound = timerMap[sortedTimerKey[0]]

    # get the number of network flows
    flows = fa.extractTCPFlows(entryList)

    print "# of QoE network events: " + str(len(timerMap))
    print "# of TCP flows: " + str(len(flows))

    # interation through all the IP packets to evalute the seperation on QoE labeled trace
    ipResult = {"outRange": 0.0, \
                "total": 0.0}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID:
            ipResult["total"] += 1
            [isInRange, tsInput] = util.checkWhetherEntryInTimerMap(entry, timerMap)
            if isInRange != True and tsInput != None:
                ipResult["outRange"] += 1
                # IP time, nearest action, 
                if tsInput in timerMap:
                    print util.convert_ts_in_human(entry.timestamp) + \
                          const.DEL + timerMap[tsInput][1].action + \
                          const.DEL + util.convert_ts_in_human(timerMap[tsInput][1].timestamp) + \
                          const.DEL + util.convert_ts_in_human(timerMap[tsInput][2].timestamp)
                #elif tsInput > lowerBound:
                #    print "Out of range: " + util.convert_ts_in_human(entry.timestamp)

    print "*" * 50
    print "*" * 50
    ratio = ipResult["outRange"] / ipResult["total"]
    print "%.3f / %.3f = %.3f" % (ipResult["outRange"], ipResult["total"], ratio)

# Check whether all the flow could be bounded by QoE trace
def checkWhetherFlowBoundedByQoE(entryList, qoeFile, client_ip, \
                                 carrier=const.TMOBILE, \
                                 network_type=const.WCDMA):
    # import the user level trace
    qoeEvent = QoE(qoeFile)

    # get the network event map
    netEventMap = qoeEvent.getNetworkEventMap(const.QOE_TIME_OFFSET)
    sortedEventTimes = sorted(netEventMap.keys())

    # get flows and flowMap
    flows = fa.extractTCPFlows(entryList)
    flowTimerMap = fa.convertIntoFlowTimerMap(flows)

    nonMappedFlow = []
    for flowStartTime in flowTimerMap.keys():
        netStartTime = util.binary_search_largest_smaller_value(flowStartTime, sortedEventTimes)
        if netStartTime != None:
            if netEventMap[netStartTime][0] < flowTimerMap[flowStartTime][0]:
                nonMappedFlow.append(flowTimerMap[flowStartTime][1])
                print "Non-mapped flow length is " + str(flowTimerMap[flowStartTime][0] - flowStartTime)

    print "*"*50
    print "*"*50
    print "Non-mapped ratio %.3f / %.3f = %.3f" % (float(len(nonMappedFlow)), float(len(flows)), \
                                                   float(len(nonMappedFlow)) / float(len(flows)))
    print "Non mapped flow length distribution is " + str(util.quartileResult(\
          sorted([f.flow[-1].timestamp - f.flow[0].timestamp for f in nonMappedFlow])))
    

#################################################################
######################### Helper Func ###########################
#################################################################
# Deprecated!
# Finding the best flow period that fits into the range of the QoE bound
def findBestFlow(flowMap, qoeStartTs, qoeEndTs):
    sortedFlowStartTime = sorted(flowMap.keys())
    flowIndex= util.binary_search_smallest_greater_index(qoeStartTs - const.QOE_TIME_OFFSET, \
                                                         0, sortedFlowStartTime)
    if flowIndex == None:
        return None

    # must increase by one to get the flow less than the QoE lower bound
    for index in range(flowIndex + 1, len(sortedFlowStartTime)):
        curStartTS = sortedFlowStartTime[index]
        if curStartTS in flowMap and \
           qoeStartTs - const.QOE_TIME_OFFSET > curStartTS and \
           qoeEndTs + const.QOE_TIME_OFFSET < flowMap[curStartTS][0]:
            return flowMap[curStartTS][1]

    return None


# Finding the QoE based IP flow by searching for the majority IP packets
# that belongs to the same flow
# Assume flow analysis is done
#
# Output:
# 1. the max flow
# 2. the corresponding IP list
def findCorrespondingIPPackets(entryList, qoeStartTS, qoeEndTS):
    entryLen = len(entryList)
    zoomIn_start_index = util.binary_search_smallest_greater_timestamp_entry_id( \
                         qoeStartTS - const.QOE_TIME_OFFSET, \
                         0, entryLen - 1, entryList)
    zoomIn_end_index = util.binary_search_largest_smaller_timestamp_entry_id( \
                         qoeEndTS + const.QOE_TIME_OFFSET, \
                         0, entryLen - 1, entryList)
    if zoomIn_start_index != None and \
       zoomIn_end_index != None:
        ipFlowMap = {}
        for index in range(zoomIn_start_index, zoomIn_end_index + 1):
            entry = entryList[index]
            if entry.logID == const.PROTOCOL_ID and \
               entry.tcp["flow"] != None:
                if entry.tcp["flow"] not in ipFlowMap:
                    ipFlowMap[entry.tcp["flow"]] = []
                ipFlowMap[entry.tcp["flow"]].append(entry)
        # find the max number of flow
        maxLen = 0
        maxList = []
        maxFlow = None
        for flow, ipList in ipFlowMap.items():
            if len(ipList) > maxLen:
                maxLen = len(ipList)
                maxList = ipList
                maxFlow = flow
        return (maxFlow, maxList)
        
    return (None, None)
