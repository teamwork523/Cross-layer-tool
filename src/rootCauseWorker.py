#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   11/17/2013

Root Cause Analysis for
1. Abnormal inferred RRC state
"""

import os, sys, time
import const
import crossLayerWorker as clw
import delayWorker as dw
import flowAnalysis as fa
import retxWorker as rw
import rrcTimerWorker as rtw
import Util as util
import validateWorker as vw

RRC_STATE_TRANSITION_DEBUG = False
NONCERTAIN_INFO_DEBUG = False
INACCURATE_TRANSITION_DEBUG = False

############################################################################
############################### RRC States #################################
############################################################################
# Root cause analysis for the abnormal state information (injected UDP uplink WCDMA)
# Only the last UDP trial packet is instrumented
#
# Output
# (a) tabluar result for lower layer features
# 1. Inter-packet timing (s)
# 2.1 Transmission Delay (ms)
# 2.2 Normalized Transmission Delay (ms)
# 3. OTA Delay (ms)
# 4. RLC Retransmission Ratio
# 5. RLC Retransmission Count
# 6. RSCP
# 7. ECIO
# 8. # of PRACH Reset message
# 9. # of PRACH Done message
# 10. # of radioBearerReconfiguration (DCH to FACH)
# 11. # of radioBearerReconfiguration (FACH to PCH)
# 12. # of physicalChannelReconfiguration
# 13. # of DL_BCCH_BCH_count
# For mannual insepection
# 10. UDP packet timestamp
# 11. First mapped RLC PDU timestamp
# 12. Last mapped RLC PDU timestamp

def abnormal_rrc_fach_analysis(entryList, server_ip, network_type=const.WCDMA, carrier=const.TMOBILE):
    log_of_interest_id = None

    if network_type.lower() == "wcdma":
        log_of_interest_id = const.UL_PDU_ID
    else:
        # TODO: handle LTE here
        pass
    
    # Uniqueness analysis
    non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(entryList, log_of_interest_id)
    # RLC retransmission analysis
    [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(entryList, detail="simple")
    # Assume always use Uplink retx map
    RLCMap = RLCULReTxCountMap
    
    udp_last_trial_list = []
    priv_inter_packet_time = None
    priv_output_result = None

    # get the timer map
    rrc_trans_timer_map = rtw.getCompleteRRCStateTransitionMap(entryList, network_type, carrier)
    
    GRANULARITY = 0.5   # assume the granularity of inter-packet timing is 0.5s
    DEL = "\t"
    header =  "Inter_packet_time" + DEL + \
              "Transmission_delay" + DEL + \
              "Normalized_transmission_delay" + DEL + \
              "OTA_RTT" + DEL + \
              "RLC_retx_ratio" + DEL + \
              "RLC_retx_count" + DEL + \
              "RSCP" + DEL + \
              "ECIO" + DEL + \
              "PRACH_reset_count" + DEL + \
              "PRACH_complete_count" + DEL + \
              "Send_UDP_timestamp" + DEL + \
              "First_Mapped_RLC_timestamp" + DEL + \
              "Last_Mapped_RLC_timestamp" + DEL + \
              "UDP_RTT" + DEL + \
              "Receive_UDP_timestamp" + DEL

    rrc_trans_of_interest = []
    if network_type == const.WCDMA:
        if carrier == const.TMOBILE:
            header += "DCH_to_FACH_Demotion_timer" + DEL + \
                      "FACH_to_PCH_Demotion_timer" + DEL + \
                      "PCH_to_FACH_Promotion_timer" + DEL + \
                      "FACH_to_DCH_Promotion_timer"
            rrc_trans_of_interest = [const.DCH_TO_FACH_ID, \
                                     const.FACH_TO_PCH_ID, \
                                     const.PCH_TO_FACH_ID, \
                                     const.FACH_TO_DCH_ID]
        elif carrier == const.ATT:
            header += "DCH_to_Disconnected_Demotion_timer" + DEL + \
                      "Disconnected_to_DCH_Promotion_timer"
            rrc_trans_of_interest = [const.DISCONNECTED_TO_DCH_ID, \
                                     const.DCH_TO_DISCONNECTED_ID]
    elif network_type == const.LTE:
        # TODO: add LTE here if necessary
        pass

    header += "Reset_delay" + DEL + \
              "IP_to_first_RLC"
    print header

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.UDP_ID and \
           entry.ip["dst_ip"] == server_ip:
            inject_num_list = extract_inject_information( \
                              entry.hex_dump["payload"][const.Payload_Header_Len+entry.ip["header_len"]+const.UDP_Header_Len:])
            if inject_num_list:
                # Inter-packet timing
                cur_inter_packet_time = inject_num_list[0] * GRANULARITY
                cur_output_result = str(cur_inter_packet_time) + DEL

                # apply cross layer mapping
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
                if mapped_RLCs:
                    if vw.is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                        if vw.is_valid_first_hop_latency_estimation(mapped_RLCs, mapped_sn, log_of_interest_id):
                            cur_output_result += gen_line_of_root_cause_info(entryList, i, mapped_RLCs, RLCMap, log_of_interest_id, DEL)
                            
                            # Compare with previous round to make sure 
                            # print out the last control message
                            if priv_inter_packet_time == None:
                                priv_inter_packet_time = cur_inter_packet_time
                                priv_output_result = cur_output_result
                                continue
                            else:
                                if cur_inter_packet_time != priv_inter_packet_time:
                                    print priv_output_result
                                # append the UDP RTT here
                                (next_ip, dummy) = util.find_nearest_ip(entryList, i, True, src_ip=server_ip)
                                udp_rtt = 0.0
                                if next_ip != None:
                                    udp_rtt = next_ip.timestamp - entry.timestamp
                                cur_output_result += str(udp_rtt) + DEL
                                # append the corresponding UDP timestamp
                                cur_output_result += util.convert_ts_in_human(next_ip.timestamp) + DEL

                                # find the nearest the demotion timer
                                rest_delay = udp_rtt
                                for rrc in rrc_trans_of_interest:
                                    overlap_timer = util.find_overlapped_transition_period(entry.timestamp, \
                                                                                           next_ip.timestamp, \
                                                                                           rrc_trans_timer_map, \
                                                                                           rrc, \
                                                                                           mode="both")
                                    rest_delay -= overlap_timer
                                    cur_output_result += str(overlap_timer) + DEL
                                # append the rest delay here
                                cur_output_result += str(rest_delay) + DEL
                                # find the IP to the first RLC
                                cur_output_result += str(mapped_RLCs[-1][0].timestamp - entry.timestamp) + DEL
                                
                                # reset everything all the time
                                priv_inter_packet_time = cur_inter_packet_time
                                priv_output_result = cur_output_result
                        else:
                            if NONCERTAIN_INFO_DEBUG:
                                print >> sys.stderr, "No polling bit ERROR: not confident about \
                                         first hop latency estimation for " + str(inject_num_list)
                                continue
                    else:
                        if NONCERTAIN_INFO_DEBUG:
                            print >> sys.stderr, "Uniqueness Analysis ERROR: not unique chain for " + str(inject_num_list)
                            continue
                else:
                    if NONCERTAIN_INFO_DEBUG:
                        print >> sys.stderr, "Cross-layer mapping ERROR: no mapping found for " + str(inject_num_list)
                        continue

    # print the last result as well
    if priv_output_result != "":
        print priv_output_result


# Root cause for RRC state transition delay (per direction)
# 
# Step 1: Label Packets of interest. 
# Step 2: Generate RLC layer features
#
# Output the following column
# 1. RRC state type
# 2. TCP RTT
# 3.1 Transmission Delay (ms)
# 3.2 Normalized Transmission Delay (ms)
# 4. OTA Delay (ms)
# 5. RLC Retransmission Ratio
# 6. RLC Retransmission Count
# 7. RSCP
# 8. ECIO
# 8. # of PRACH Reset message
# 9. # of PRACH Done message
# For mannual insepection
# 10. UDP packet timestamp
# 11. First mapped RLC PDU timestamp
# 12. Last mapped RLC PDU timestamp
#
# Return
# 1. RRC state count
# 2. count map for detailed packet missing 
def rrc_state_transition_analysis(entryList, client_ip, network_type, direction, flow = None, header=True, carrier=const.TMOBILE):
    # statistics summarize the occurance of each state
    rrc_occurance_map = util.gen_RRC_state_count_map()

    print >> sys.stderr, "Finish RRC state count ..."

    # determine the network type
    log_of_interest_id = util.get_logID_of_interest(network_type, direction)

    # Label each IP packet with its corresponding RRC state
    (pktRRCMap, dummy) = label_RRC_state_for_IP_packets(entryList, carrier)

    print >> sys.stderr, "Finish label IP packets ..."

    # Assign TCP RTT
    dw.calc_tcp_rtt(entryList)

    print >> sys.stderr, "Finish TCP RTT calculation ..."

    # Uniqueness analysis
    non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(entryList, log_of_interest_id)

    print >> sys.stderr, "Finish uniqueness analysis ..."

    # RLC retransmission analysis
    [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(entryList, detail="simple")

    print >> sys.stderr, "Finish retransmission analysis ..."

    RLCMap = None
    if direction.lower() == "up":
        RLCMap = RLCULReTxCountMap
    elif direction.lower() == "down":
        RLCMap = RLCDLReTxCountMap

    # Output the header
    DEL = "\t"
    header = "RRC_state" + DEL + \
             "TCP_RTT" + DEL + \
             "Transmission_delay" + DEL + \
             "Normalized_transmission_delay" + DEL + \
             "OTA_RTT" + DEL + \
             "RLC_retx_ratio" + DEL + \
             "RLC_retx_count" + DEL + \
             "RSCP" + DEL + \
             "ECIO" + DEL + \
             "PRACH_reset_count" + DEL + \
             "PRACH_complete_count" + DEL + \
             "UDP_timestamp" + DEL + \
             "First_Mapped_RLC_timestamp" + DEL + \
             "Last_Mapped_RLC_timestamp"
    
    if flow != None:
        header += DEL + "Hostname" + DEL + "Interval"
    if header == True:
        print header

    packet_count = {"total":0.0, "mapped":0.0, "unique":0.0, "valid_rtt":0.0}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.TCP_ID:
            if direction.lower() == "up" and entry.ip["src_ip"] != client_ip or \
               direction.lower() == "down" and entry.ip["dst_ip"] != client_ip:
                continue
            mapped_RLCs = mapped_sn = None
            if direction.lower() == "up" and entry.ip["src_ip"] == client_ip:
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
            elif direction.lower() == "down" and entry.ip["dst_ip"] == client_ip:
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(entryList, i, log_of_interest_id)
            packet_count["total"] += 1
            if mapped_RLCs:
                packet_count["mapped"] += 1
                if vw.is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                    packet_count["unique"] += 1
                    if entry.rtt["tcp"] and entry in pktRRCMap:
                        packet_count["valid_rtt"] += 1
                        cur_output_result = str(const.RRC_MAP[pktRRCMap[entry]]) + DEL + \
                                            str(entry.rtt["tcp"]) + DEL
                        cur_output_result += gen_line_of_root_cause_info(entryList, i, mapped_RLCs, RLCMap, log_of_interest_id, DEL)
                        # Flow level analysis
                        if flow != None and \
                           entry.tcp["flow"] != None and \
                           entry.tcp["flow"].properties["http"] != None:
                            cur_output_result += str(entry.tcp["flow"].properties["http"]["host"]) + DEL +\
                                                 str(entry.tcp["flow"].properties["http"]["timer"])
                            print cur_output_result 
                        else:
                            print cur_output_result
                        # increment that RRC state's count
                        rrc_occurance_map[pktRRCMap[entry]] += 1.0
                    else:
                        if NONCERTAIN_INFO_DEBUG:
                            if entry in pktRRCMap:
                                print >> sys.stderr, "TCP RTT estimation failed ERROR at " + util.convert_ts_in_human(entry.timestamp) \
                                                     + " with " + const.RRC_MAP[pktRRCMap[entry]]
                            continue
                else:
                    if NONCERTAIN_INFO_DEBUG:
                        if entry in pktRRCMap:
                            print >> sys.stderr, "Uniqueness Analysis ERROR at " + util.convert_ts_in_human(entry.timestamp) \
                                                 + " with " + const.RRC_MAP[pktRRCMap[entry]]
                        continue
            else:
                if NONCERTAIN_INFO_DEBUG:
                    if entry in pktRRCMap:
                        print >> sys.stderr, "Cross-layer mapping ERROR at " + util.convert_ts_in_human(entry.timestamp) \
                                             + " with " + const.RRC_MAP[pktRRCMap[entry]]
                    continue

    return rrc_occurance_map, packet_count

# print transition timer values
def rrc_state_transition_timers(entryList):
    (dummy, rrc_trans_timer_map) = label_RRC_state_for_IP_packets(entryList)
    for rrc in rrc_trans_timer_map.keys():
        print "%s has distirbution %s" % (const.RRC_MAP[rrc], util.quartileResult(rrc_trans_timer_map[rrc]))    
    

############################################################################
######################## Application Implication ###########################
############################################################################
# Performance analysis for control browsing trace
#
# 1. Pair the possible interrupted flow with the non-interrupted flow
# 2. Compare the problematic TCP packet and the corresponding normal packet
def performance_analysis_for_browsing(entryList, flows, client_ip, network_type, \
                                      target_timer=1000.0, problem_timer=7000.0, \
                                      carrier=const.TMOBILE):
    DEL = "\t"
    # build the target and problem trace
    timerMap = {}
    for url in const.HOST_OF_INTEREST:
        # timerMap[url] = {target_timer:[], problem_timer:[]}
        timerMap[url] = {"good":[], "bad":[]}

    for f in flows:
        if f.properties["http"] != None and \
           f.properties["http"]["host"] in const.HOST_OF_INTEREST:
           #(f.properties["http"]["timer"] == target_timer or \
           # f.properties["http"]["timer"] == problem_timer):
            flowTrace = f.getCrossLayerTrace(entryList)
            traceStartIndex = None
            traceEndIndex = None

            interferenceMap = {}    # packet_index : RLC_index
            flowIndex = 1

            # Assign RTT for the trace
            dw.calc_tcp_rtt(flowTrace)

            # Check whether the current flow contains problematic traces
            inaccurateMap = findInaccurateRRCPackets(flowTrace)

            for i in range(len(flowTrace)):
                request = flowTrace[i]

                if request.logID == const.PROTOCOL_ID:
                    mapped_RLCs = mapped_sn = None
                    if request.ip["src_ip"] == client_ip:
                        # determine the network type
                        log_of_interest_id = util.get_logID_of_interest(network_type, "up")
                        mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(flowTrace, i, log_of_interest_id)
                    elif request.ip["dst_ip"] == client_ip:
                        log_of_interest_id = util.get_logID_of_interest(network_type, "down")
                        mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(flowTrace, i, log_of_interest_id)
                    else:
                        continue

                    if mapped_RLCs:
                        interferenceMap[mapped_RLCs[0][-1]] = flowIndex
                        if traceStartIndex == None or \
                           mapped_RLCs[0][-1] < traceStartIndex:
                            traceStartIndex = mapped_RLCs[0][-1]
                        if traceEndIndex == None or \
                           mapped_RLCs[-1][-1] > traceEndIndex:
                            traceEndIndex = mapped_RLCs[-1][-1]
                    flowIndex += 1

            if traceStartIndex != None and traceEndIndex != None:
                # Future RTT value
                RTT = "N/A"
                if traceEndIndex > len(flowTrace):
                    traceEndIndex = len(flowTrace) - 1
                interfered_states, interfered_indices = checkRRCStateTransOccur(flowTrace, traceStartIndex, traceEndIndex, carrier)
                # check whether there is a chance to update RTT
                rtts = util.getListOfRTTBasedonIndices(flowTrace, interfered_indices, src_ip = client_ip)
                if len(rtts) > 0:
                    RTT = util.getMedian(rtts) 
                lastData = fa.findLastPayload(f.flow)
                
                # Header: hostname, interference type, user delay, http embeddied timer, 
                #         SYN to the last IP packet, Interference time
                # not None means bad
                if lastData.timestamp - f.flow[0].timestamp > const.MAX_USER_DELAY_SEC:
                    continue
                line = f.properties["http"]["host"] + DEL
                # Disable inaccurate case for now   
                #if len(inaccurateMap) > 0:
                    # detect abnormal state occurs in between state transitions
                    #line += "Inaccurate" + DEL
                # NEW: add carrier
                if const.PCH_TO_FACH_ID in interfered_states and const.FACH_TO_DCH_ID in interfered_states:
                    #timerMap[f.properties["http"]["host"]]["bad"].append(lastData.timestamp - f.flow[0].timestamp)
                    line += const.RRC_MAP[const.PCH_TO_FACH_ID] + "+" + const.RRC_MAP[const.FACH_TO_DCH_ID] + DEL
                elif const.PCH_TO_FACH_ID in interfered_states:
                    line += const.RRC_MAP[const.PCH_TO_FACH_ID] + DEL
                elif const.FACH_TO_DCH_ID in interfered_states:
                    line += const.RRC_MAP[const.FACH_TO_DCH_ID] + DEL
                elif const.DISCONNECTED_TO_DCH_ID in interfered_states:
                    line += const.RRC_MAP[const.DISCONNECTED_TO_DCH_ID] + DEL
                else:
                    #timerMap[f.properties["http"]["host"]]["good"].append(lastData.timestamp - f.flow[0].timestamp)
                    # Find the RTTs in the trace
                    rtts = util.getListOfRTT(flowTrace, src_ip = client_ip)
                    if len(rtts) > 0:
                        RTT = util.getMedian(rtts)
                    line += "Normal" + DEL
                
                line += str(lastData.timestamp - f.flow[0].timestamp) + DEL
                # http embeddied timer
                if f.properties["http"]["timer"] != None:
                    line += ("%.3f" % (f.properties["http"]["timer"])) +DEL
                else:
                    continue
                # SYN to last IP
                lastIPpacketBeforeFlow = f.getLastPacketBeforeFlow(entryList)
                if lastIPpacketBeforeFlow != None:
                    line += str(f.flow[0].timestamp - lastIPpacketBeforeFlow.timestamp) + DEL
                else:
                    line += "None" + DEL
                # Average over all Interference from FACH_to_DCH promotion
                interfer_time = []
                for state_index in range(len(interfered_states)):
                    # PCH_to_FACH interfer time
                    if interfered_states[state_index] == const.FACH_ID:
                        (priv_IP, dummy) = util.find_nearest_ip(flowTrace, interfered_indices[state_index])
                        (later_IP, dummy) = util.find_nearest_ip(flowTrace, interfered_indices[state_index], inverse = True)
                        if priv_IP != None and later_IP != None:
                            interfer_time.append(later_IP.timestamp - priv_IP.timestamp)
                    elif interfered_states[state_index] == const.DCH_ID:
                        (priv_IP, dummy) = util.find_nearest_ip(flowTrace, interfered_indices[state_index])
                        finish_index = findNextRadioBearerConfiguration(flowTrace, interfered_indices[state_index])
                        if finish_index != None:
                            (later_IP, dummy) = util.find_nearest_ip(flowTrace, finish_index, inverse = True)
                            if priv_IP != None and later_IP != None:
                                interfer_time.append(later_IP.timestamp - priv_IP.timestamp)
                if len(interfer_time) > 0:
                    line += str(sum(interfer_time)) + DEL
                else:
                    line += "0.0" + DEL
                
                if RTT != "N/A":
                    line += str(RTT) + DEL
                    print line

    # print result
    """
    i = 0.5
    for url in sorted(const.HOST_OF_INTEREST):
        line = url + DEL + str(i) + DEL
        badUserTimes = util.quartileResult(timerMap[url]["bad"])
        goodUserTimes  = util.quartileResult(timerMap[url]["good"])
        line += str(badUserTimes[2]) + DEL + str(badUserTimes[0]) + DEL + str(badUserTimes[-1]) + DEL
        line += str(goodUserTimes[2]) + DEL + str(goodUserTimes[0]) + DEL + str(goodUserTimes[-1]) + DEL
        line += str(badUserTimes[2] - goodUserTimes[2]) + DEL + \
                str(badUserTimes[0] - goodUserTimes[0]) + DEL + \
                str(badUserTimes[-1] - goodUserTimes[-1])
        print line
        i += 1
    """

############################################################################
############################### Case Study #################################
############################################################################
# Print the detail information for the a general trace
def trace_detail_rrc_info(entryList, client_ip, network_type):
    DEL = "\t"
    IP_type = "IP"
    IP_value = 3
    RLC_begin_type = "RLC_begin"
    RLC_begin_value = 3
    RLC_end_type = "RLC_end"
    RLC_end_value = 2
    Demotion_interfer_begin_type = "Demotion_interference_begin"
    Demotion_interfer_end_type = "Demotion_interference_end"
    Demotion_interfer_value = 3
    Promotion_interfer_begin_type = "Promotion_interference_begin"
    Promotion_interfer_end_type = "Promotion_interference_end"
    Promotion_interfer_value = 3

    # Label each IP packet with its corresponding RRC state
    (pktRRCMap, dummy) = label_RRC_state_for_IP_packets(entryList)
    DCH_to_FACH_demotion = False
    FACH_to_DCH_promotion = False
    for i in range(len(entryList)):
        entry = request = entryList[i]

        if request.logID == const.PROTOCOL_ID:
            mapped_RLCs = mapped_sn = None
            if request.ip["src_ip"] == client_ip:
                # determine the network type
                log_of_interest_id = util.get_logID_of_interest(network_type, "up")
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
            elif request.ip["dst_ip"] == client_ip:
                log_of_interest_id = util.get_logID_of_interest(network_type, "down")
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(entryList, i, log_of_interest_id)
            else:
                continue

            if mapped_RLCs:
                # add type ID
                line = IP_type + DEL
                # add IP packet relative time
                line += str(request.timestamp) + DEL
                # append the RRC state
                if request in pktRRCMap and pktRRCMap[request] in const.RRC_MAP:
                    line += str(pktRRCMap[request]) + DEL +\
                            str(const.RRC_MAP[pktRRCMap[request]]) + DEL
                else:
                    if request.rrcID in const.RRC_MAP:
                        line += str(request.rrcID) + DEL + \
                                str(const.RRC_MAP[request.rrcID]) + DEL
                    else:
                        line += "N/A" + DEL + "N/A" + DEL
                # add the TCP type
                if request.http["type"] == "GET":
                    line += request.http["type"] + DEL
                else:
                    line += util.get_tcp_flag_info(request, "+") + DEL
                # append packet size
                pkt_size = request.ip["total_len"] - request.ip["header_len"]
                if request.ip["tlp_id"] == const.TCP_ID:
                    pkt_size -= request.tcp["header_len"]
                elif request.ip["tlp_id"] == const.UDP_ID:
                    pkt_size -= const.UDP_Header_Len
                line += str(pkt_size) + DEL
                line += util.convert_ts_in_human(request.timestamp) + DEL
                print line

                # Mapped Lower layer packet time
                beginRRC = None
                lastRRC = None
                if mapped_RLCs[0][0].rrcID in const.RRC_MAP:
                    beginRRC = const.RRC_MAP[mapped_RLCs[0][0].rrcID]
                if mapped_RLCs[-1][0].rrcID in const.RRC_MAP:
                    lastRRC = const.RRC_MAP[mapped_RLCs[-1][0].rrcID] 
                print RLC_begin_type + DEL + \
                      str(mapped_RLCs[0][0].timestamp) + \
                      DEL + str(beginRRC) + \
                      DEL + util.convert_ts_in_human(mapped_RLCs[0][0].timestamp)
                print RLC_end_type + DEL + \
                      str(mapped_RLCs[-1][0].timestamp) + \
                      DEL + str(lastRRC) + \
                      DEL + util.convert_ts_in_human(mapped_RLCs[-1][0].timestamp)
                
        elif request.logID == const.SIG_MSG_ID:
            # TODO: add AT&T here
            entry = request
            line = ""
            # FACH -> PCH start
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfiguration":
                line += "FACH_to_PCH_start" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Demotion_interfer_value)
            # FACH -> PCH end
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfigurationComplete":
                line += "FACH_to_PCH_end" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Demotion_interfer_value)
            # DCH -> FACH start
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                DCH_to_FACH_demotion = True
                line += "DCH_to_FACH_start" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Demotion_interfer_value)
            # DCH -> FACH end / FACH -> DCH end
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfigurationComplete":
                line += str(request.timestamp) + DEL + \
                       str(Demotion_interfer_value) + DEL
                if DCH_to_FACH_demotion:
                    line = "DCH_to_FACH_end" + DEL + line
                    DCH_to_FACH_demotion = False
                if FACH_to_DCH_promotion:
                    line = "FACH_to_DCH_end" + DEL + line
                    FACH_to_DCH_promotion = False
            # FACH -> DCH start
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfiguration" and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                FACH_to_DCH_promotion = True
                line += "FACH_to_DCH_start" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Promotion_interfer_value)
            # PCH -> FACH start
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdate":
                line += "PCH_to_FACH_start" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Promotion_interfer_value)
            # PCH -> FACH end
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdateConfirm" and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                line += "PCH_to_FACH_end" + DEL + \
                        str(request.timestamp) + DEL + \
                        str(Promotion_interfer_value)
            if line != "":		
                line += util.convert_ts_in_human(request.timestamp)
                print line
			

# Print the relative time of IP packet and corresponding RLC PDUs for each flow
# Also include the interfered timestamp
def flow_timeseries_info(entryList, flows, client_ip, network_type, mediaLog=None, \
                         carrier=const.TMOBILE):
    DEL = "\t"
    IP_type = "IP"
    IP_value = 3
    RLC_begin_type = "RLC_begin"
    RLC_begin_value = 3
    RLC_end_type = "RLC_end"
    RLC_end_value = 2
    Demotion_interfer_begin_type = "Demotion_interference_begin"
    Demotion_interfer_end_type = "Demotion_interference_end"
    Demotion_interfer_value = 3
    Promotion_interfer_begin_type = "Promotion_interference_begin"
    Promotion_interfer_end_type = "Promotion_interference_end"
    Promotion_interfer_value = 3

    # Video related
    stallMap = None
    bufferMap = None
    if mediaLog != None:
        stallMap = mediaLog.getStallPeriodMap()
        bufferMap = mediaLog.getBufferMap()
    
    # Label each IP packet with its corresponding RRC state
    (pktRRCMap, dummy) = label_RRC_state_for_IP_packets(entryList, carrier)
    #dw.calc_tcp_rtt(entryList)

    # Assign TCP RTT
    # dw.calc_tcp_rtt(entryList)

    # Uniqueness analysis
    # non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(entryList, log_of_interest_id)

    # flow level analysis
    for flow in flows:
        # TODO: adjust this for certain type of analysis
        #if flow.properties["http"] != None and flow.properties["http"]["host"] in const.HOST_OF_INTEREST:
        if flow.properties["http"] != None:
            flowTrace = flow.getCrossLayerTrace(entryList)
            flowBegin = True
            baseTime = flow.flow[0].timestamp
            DCH_to_FACH_demotion = False
            FACH_to_DCH_promotion = False

            # Estimate the RTT in this case
            dw.calc_tcp_rtt(flowTrace)

            # get the inaccurate IP packet map
            inaccurateMap = findInaccurateRRCPackets(flowTrace)

            print "*" * 60
            print flow.properties["http"]
            print "Start time: " + util.convert_ts_in_human(flow.flow[0].timestamp)
            print "End time: " + util.convert_ts_in_human(flow.flow[-1].timestamp)
            print "*" * 60

            for i in range(len(flowTrace)):
                request = flowTrace[i]
                if request.logID == const.PROTOCOL_ID:
                    flowBegin = True
                    mapped_RLCs = mapped_sn = None
                    if request.ip["src_ip"] == client_ip:
                        # determine the network type
                        log_of_interest_id = util.get_logID_of_interest(network_type, "up")
                        mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(flowTrace, i, log_of_interest_id)
                    elif request.ip["dst_ip"] == client_ip:
                        log_of_interest_id = util.get_logID_of_interest(network_type, "down")
                        mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(flowTrace, i, log_of_interest_id)
                    else:
                        continue

                    if mapped_RLCs:
                        # add type ID
                        line = IP_type + DEL
                        # add IP packet relative time
                        line += str(request.timestamp - baseTime) + DEL
                        # append the RRC state
                        if request in pktRRCMap and pktRRCMap[request] in const.RRC_MAP:
                            line += str(pktRRCMap[request]) + DEL +\
                                    str(const.RRC_MAP[pktRRCMap[request]]) + DEL
                        else:
                            if request.rrcID in const.RRC_MAP:
                                line += str(request.rrcID) + DEL + \
                                        str(const.RRC_MAP[request.rrcID]) + DEL
                            else:
                                line += str(request.rrcID) + DEL + "N/A" + DEL
                        # add the TCP type
                        if request.http["type"] == "GET":
                            line += request.http["type"] + DEL
                        else:
                            line += util.get_tcp_flag_info(request, "+") + DEL
                        # append packet size
                        pkt_size = request.ip["total_len"] - request.ip["header_len"] \
                                   - request.tcp["header_len"]
                        line += str(pkt_size) + DEL
                        # check whether the current IP packet is inaccurate or not
                        if request in inaccurateMap:
                            line += "WRONG:" + str(inaccurateMap[request]) + DEL
                        else:
                            line += "CORRECT" + DEL
                        
                        # insert Vedio related information if possible
                        if stallMap != None and len(stallMap) > 0:
                            if checkWhetherAIPpacketInStall(request, stallMap):
                                line += "STALLED" + DEL
                                if request.rrcID != const.DCH_ID and request.rrcID != None:
                                    print "ISSUEs"
                            else:
                                line += "NORMAL" + DEL
                        if bufferMap != None and len(bufferMap) > 0:
                            buffering = checkMostRecentBufferingPoint(request, bufferMap)
                            if buffering != None:
                                line += str(buffering) + DEL
                            else:
                                line += "N/A" + DEL

                        # check RTT
                        if request.rtt["tcp"] != None:
                            line += str(request.rtt["tcp"]) + DEL
                        else:
                            line += "No_RTT" + DEL

                        # only print downloading payload greater than 0 in this case
                        if mediaLog != None:
                            if pkt_size > 0:
                                print line
                                # Mapped Lower layer packet time
                                print RLC_begin_type + DEL + \
                                      str(mapped_RLCs[0][0].timestamp - baseTime) + \
                                      DEL + str(RLC_begin_value)
                                print RLC_end_type + DEL + \
                                      str(mapped_RLCs[-1][0].timestamp - baseTime) + \
                                      DEL + str(RLC_end_value)
                        else:
                            print line
                            # Mapped Lower layer packet time
                            print RLC_begin_type + DEL + \
                                  str(mapped_RLCs[0][0].timestamp - baseTime) + \
                                  DEL + str(RLC_begin_value)
                            print RLC_end_type + DEL + \
                                  str(mapped_RLCs[-1][0].timestamp - baseTime) + \
                                  DEL + str(RLC_end_value)
                        
                elif flowBegin and request.logID == const.SIG_MSG_ID:
                    entry = request
                    # T-Mobile
                    if carrier == const.TMOBILE:
                        # FACH -> PCH start
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfiguration":
                            print "FACH_to_PCH_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Demotion_interfer_value)
                        # FACH -> PCH end
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfigurationComplete":
                            print "FACH_to_PCH_end" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Demotion_interfer_value)
                        # DCH -> FACH start
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                           entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                            DCH_to_FACH_demotion = True
                            print "DCH_to_FACH_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Demotion_interfer_value)
                        # DCH -> FACH end / FACH -> DCH end
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfigurationComplete":
                            line = str(request.timestamp - baseTime) + DEL + \
                                   str(Demotion_interfer_value) + DEL
                            if DCH_to_FACH_demotion:
                                line = "DCH_to_FACH_end" + DEL + line
                                DCH_to_FACH_demotion = False
                            if FACH_to_DCH_promotion:
                                line = "FACH_to_DCH_end" + DEL + line
                                FACH_to_DCH_promotion = False
                            print line
                        # FACH -> DCH start
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfiguration" and \
                           entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                            FACH_to_DCH_promotion = True
                            print "FACH_to_DCH_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                        # PCH -> FACH start
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdate":
                            print "PCH_to_FACH_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                        # PCH -> FACH end
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdateConfirm" and \
                           entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                            print "PCH_to_FACH_end" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                    elif carrier == const.ATT:
                        # DISCONNECTED to DCH start
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_REQUEST:
                            print "DISCONNECTED_to_DCH_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                        # Disconnected to DCH ends
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_SETUP_COMPLETE:
                            print "DISCONNECTED_to_DCH_end" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                        # DCH to Disconnected starts
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE:
                            print "DCH_to_DISCONNECTED_start" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)
                        # DCH to Disconnected ends
                        if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE_COMPLETE:
                            print "DCH_to_DISCONNECTED_end" + DEL + \
                                  str(request.timestamp - baseTime) + DEL + \
                                  str(Promotion_interfer_value)

            #lastData = fa.findLastPayload(flow.flow)
            #print "User Experienced Delay is " + str(lastData.timestamp - flow.flow[0].timestamp)
                        
# Video analysis
def video_analysis(entryList, mediaLog, carrier=const.TMOBILE):
    bufferMap = mediaLog.getBufferMap()
    stallMap = mediaLog.getStallPeriodMap()
    (pktMap, timerMap) = label_RRC_state_for_IP_packets(entryList, carrier)
    sortedStallBeign = sorted(stallMap.keys())

    """
    inaccurateIPMap = findInaccurateRRCPackets(entryList)

    if len(inaccurateIPMap) > 0:
        print "Yep!!! Find inaccurate RRC IP packets"
        
        for ip in inaccurateIPMap.keys():
            beginTS = util.binary_search_largest_smaller_value(ip.timestamp, sortedStallBeign)
            if beginTS in stallMap and ip.timestamp <= stallMap[beginTS]:
                print "REAL PROBLES: " + str(inaccurateIPMap[ip])
            else:
                print "Better luck next time: " + str(inaccurateIPMap[ip])
    else:
        print "No such cases!!!"
    """
    
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID:
            beginTS = util.binary_search_largest_smaller_value(entry.timestamp, sortedStallBeign)
            if beginTS in stallMap and entry.timestamp <= stallMap[beginTS]:
                if entry in pktMap:
                    print const.RRC_MAP[pktMap[entry]]

############################################################################
############################# Helper Function ##############################
############################################################################
# Video related
# check whether a certain IP packet in a stall or not
def checkWhetherAIPpacketInStall(entry, stallMap):
    stallBeginTimeSortedList = sorted(stallMap.keys())
    beginTS = util.binary_search_largest_smaller_value(entry.timestamp, stallBeginTimeSortedList)
    if beginTS in stallMap and entry.timestamp <= stallMap[beginTS]:
        return True
    return False

# Video related
# check the most recent buffering period
def checkMostRecentBufferingPoint(entry, bufferMap):
    bufferingSortedTimeList = sorted(bufferMap.keys())
    bufferTS = util.binary_search_largest_smaller_value(entry.timestamp, bufferingSortedTimeList)
    if bufferTS in bufferMap:
        return bufferMap[bufferTS]
    return None

# Extract the injected number with format xx:yy;
#
# Output:
# List of injected number (assume integer)
def extract_inject_information(payload):
    terminate_index = None
    UPPER_BOUND = 10 # assume the hijected information is less than 10 bytes
    for i in range(len(payload)):
        if i > UPPER_BOUND:
            break
        if payload[i].decode("hex") == ";":
            terminate_index = i
            break

    if terminate_index != None:
        try:
            return [int(x) for x in "".join(payload[:terminate_index]).decode("hex").split(":")]
        except ValueError:
            return None 
    else:
        return None

# Generate a single line of output information
#
# Output the following column
# 1.1 Transmission Delay (ms)
# 1.2 Normalized Transmission Delay (ms)
# 2. OTA Delay (ms)
# 3. RLC Retransmission Ratio
# 4. RLC Retransmission Count
# 5. RSCP
# 6. ECIO
# 7. # of PRACH Reset message
# 8. # of PRACH Done message
# For mannual insepection
# 9. UDP packet timestamp
# 10. First mapped RLC PDU timestamp
# 11. Last mapped RLC PDU timestamp
def gen_line_of_root_cause_info(entryList, entryIndex, mapped_RLCs, RLCMap, log_of_interest_id, DEL):
    entry = entryList[entryIndex]
    cur_output_result = ""
    # First-hop latency                   
    transmission_delay, rlc_rtt_list = dw.calc_first_hop_latency(mapped_RLCs)
    cur_output_result += str(transmission_delay * 1000) + DEL
    # normalized transmission delay (per PDU transmission delay)
    mapped_RLCs_len = len(mapped_RLCs)
    if mapped_RLCs_len != 0:
        cur_output_result += str(transmission_delay * 1000 / mapped_RLCs_len) + DEL
    else:
        cur_output_result += str(0) + DEL
    cur_output_result += str(util.meanValue(rlc_rtt_list) * 1000) + DEL
    # RLC retx ratio and count
    (retxRLCCount, totalRLCCount) = rw.countRLCRetx([rlc[0] for rlc in mapped_RLCs], RLCMap, log_of_interest_id)
    cur_output_result += str(min(float(retxRLCCount) / float(totalRLCCount), 1.0)) + DEL
    cur_output_result += str(retxRLCCount) + DEL
    # RSCP
    if entry.sig["RSCP"] != []:
        cur_output_result += str(min(entry.sig["RSCP"])) + DEL
    else:
        cur_output_result += "N/A" + DEL
    # ECIO
    if entry.sig["ECIO"] != []:
        cur_output_result += str(min(entry.sig["ECIO"])) + DEL
    else:
        cur_output_result += "N/A" + DEL

    # PRACH related
    countMap = util.count_prach_aich_status(entryList, mapped_RLCs[0][-1], mapped_RLCs[-1][-1], const.PRACH_PARA_ID)
    cur_output_result += str(countMap[const.PRACH_ABORT]) + DEL
    cur_output_result += str(countMap[const.PRACH_DONE]) + DEL

    # WCDMA signaling message
    """
    sigCountMap = util.count_signaling_msg(entryList, mapped_RLCs[0][-1], mapped_RLCs[-1][-1])
    line = str(len(sigCountMap[const.MSG_RADIO_BEARER_RECONFIG][const.DCH_ID]))
    # plus a next radio bearer
    if len(sigCountMap[const.MSG_RADIO_BEARER_RECONFIG][const.DCH_ID]) != 0:
        line += "("
        for configurationIndex in sigCountMap[const.MSG_RADIO_BEARER_RECONFIG][const.DCH_ID]:
            configruationCompleteIndex = findNextRadioBearerConfiguration(entryList, configurationIndex)
            if configruationCompleteIndex != None:
                line += str(entryList[configruationCompleteIndex].timestamp -entryList[configurationIndex].timestamp) + ","
        line = line[:-1] +")"
    cur_output_result += line + DEL
    cur_output_result += str(len(sigCountMap[const.MSG_RADIO_BEARER_RECONFIG][const.FACH_ID])) + DEL
    cur_output_result += str(len(sigCountMap[const.MSG_PHY_CH_RECONFIG])) + DEL
    cur_output_result += str(len(sigCountMap["DL_BCCH_BCH"])) + DEL
    """

    # mannual insepection
    cur_output_result += util.convert_ts_in_human(entry.timestamp) + DEL + \
                         util.convert_ts_in_human(mapped_RLCs[0][0].timestamp) + DEL + \
                         util.convert_ts_in_human(mapped_RLCs[-1][0].timestamp) + DEL

    return cur_output_result

# Label the RRC state (Only support for WCDMA)
#
# Stable RRC states are PCH, FACH, DCH (assume assigned during pre-process)
# Transition RRC state are PCH->FACH, FACH->DCH, DCH->FACH, FACH->PCH
#
# We only care about the one packet after the state transition
#
# Output:
# 1. Map between packets and its corresponding state
# 2. A state transition timer map, i.e. PCH->FACH : [list of PCH->FACH transition period]
def label_RRC_state_for_IP_packets(entryList, carrier=const.TMOBILE, network_type=const.WCDMA):
    pktRRCMap = {}
    privPacket = None
    rrc_trans_timer_map = util.gen_RRC_trans_state_list_map(carrier, network_type)

    """
    # old labeling methods
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID and \
           entry.rrcID != None and \
           entry.ip["tlp_id"] == const.TCP_ID:
            if privPacket != None:
                if not pktRRCMap.has_key(privPacket):
                    pktRRCMap[privPacket] = privPacket.rrcID
                if privPacket.rrcID != entry.rrcID:
                    if privPacket.rrcID == const.FACH_ID:
                        if entry.rrcID == const.PCH_ID:
                            pktRRCMap[entry] = const.FACH_TO_PCH_ID
                        elif entry.rrcID == const.DCH_ID:
                            pktRRCMap[entry] = const.FACH_TO_DCH_ID
                    elif privPacket.rrcID == const.PCH_ID:
                        if entry.rrcID == const.FACH_ID:
                            pktRRCMap[entry] = const.PCH_TO_FACH_ID
                    elif privPacket.rrcID == const.DCH_ID:
                        if entry.rrcID == const.FACH_ID:
                            pktRRCMap[entry] = const.DCH_TO_FACH_ID
            privPacket = entry
    """
    
    rrc_transit_state_pkt_buffer = None
    rrc_transit_state = None
    non_rrc_transit_count = 0
    rrc_trans_begin_time = None

    for entry in entryList:
        if entry.logID == const.SIG_MSG_ID:
            # T-Mobile 3G
            if carrier == const.TMOBILE:
                # FACH -> PCH (case 1)
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_PHY_CH_RECONFIG:
                    rrc_transit_state_pkt_buffer = []
                    rrc_trans_begin_time = entry.timestamp
                    continue
                # reset FACH -> PCH (case 1)
                if rrc_transit_state_pkt_buffer != None and \
                   entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_PHY_CH_RECONFIG_COMPLETE:
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.FACH_TO_PCH_ID)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[const.FACH_TO_PCH_ID].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
                    continue
                # FACH -> PCH (case 2)
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP:
                    rrc_transit_state_pkt_buffer = []
                    rrc_trans_begin_time = entry.timestamp
                    continue
                # reset FACH -> PCH (case 2)
                if rrc_transit_state_pkt_buffer != None and \
                   entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_CCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP_CONFIRM and \
                   entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.PCH_ID:
                    if RRC_STATE_TRANSITION_DEBUG and len(rrc_transit_state_pkt_buffer) > 0:
                        print "RRC state transition: FACH_TO_PCH with count %d" % (len(rrc_transit_state_pkt_buffer))
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.FACH_TO_PCH_ID)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[const.FACH_TO_PCH_ID].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
                    continue
                # PCH -> FACH same as FACH -> PCH (case 2)
                # reset PCH -> FACH
                # TODO: current ignore cell-reselection special case
                if rrc_transit_state_pkt_buffer != None and \
                   entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP_CONFIRM and \
                   entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                    if RRC_STATE_TRANSITION_DEBUG and len(rrc_transit_state_pkt_buffer) > 0:
                        print "RRC state transition: PCH_TO_FACH with count %d" % (len(rrc_transit_state_pkt_buffer))
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.PCH_TO_FACH_ID)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[const.PCH_TO_FACH_ID].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
                    continue
                # FACH -> DCH
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                   entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                    rrc_transit_state_pkt_buffer = []
                    rrc_transit_state = const.FACH_TO_DCH_ID
                    rrc_trans_begin_time = entry.timestamp
                    continue
                # reset FACH -> DCH & reset DCH -> FACH
                if rrc_transit_state != None and rrc_transit_state_pkt_buffer != None and \
                   entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG_COMPLETE:
                    if RRC_STATE_TRANSITION_DEBUG and len(rrc_transit_state_pkt_buffer) > 0:
                        print "RRC state transition: %s with count %d" % (const.RRC_MAP[rrc_transit_state], len(rrc_transit_state_pkt_buffer))
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, rrc_transit_state)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[rrc_transit_state].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
                    rrc_transit_state == None
                    continue
                # DCH -> FACH
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                   entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                    rrc_transit_state_pkt_buffer = []
                    rrc_transit_state = const.DCH_TO_FACH_ID
                    rrc_trans_begin_time = entry.timestamp
                    continue
            # ATT 3G
            elif carrier == const.ATT:
                # Disconnected to DCH starts
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_REQUEST:
                    rrc_transit_state_pkt_buffer = []
                    rrc_trans_begin_time = entry.timestamp
                    continue
                # Disconnected to DCH ends
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_SETUP_COMPLETE:
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.DISCONNECTED_TO_DCH_ID)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[const.DISCONNECTED_TO_DCH_ID].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
                # DCH to Disconnected starts
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE:
                    rrc_transit_state_pkt_buffer = []
                    rrc_trans_begin_time = entry.timestamp
                    continue
                # DCH to Disconnected ends
                if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                   entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE_COMPLETE:
                    util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.DCH_TO_DISCONNECTED_ID)
                    if rrc_trans_begin_time != None:
                        rrc_trans_timer_map[const.DCH_TO_DISCONNECTED_ID].append(entry.timestamp - rrc_trans_begin_time)
                        rrc_trans_begin_time = None
                    rrc_transit_state_pkt_buffer = None
        elif entry.logID == const.PROTOCOL_ID and \
             entry.rrcID != None and \
             entry.ip["tlp_id"] == const.TCP_ID:
            if rrc_transit_state_pkt_buffer != None and rrc_transit_state != None:
                rrc_transit_state_pkt_buffer.append(entry)
            else:
                pktRRCMap[entry] = entry.rrcID
   

    return pktRRCMap, rrc_trans_timer_map

# Check whether state Transition occurs within a certain period
# (Currently checking whether promotion occurs)
# Output:
# 1. list of RRC indicator
# 2. list of Position of interferred
def checkRRCStateTransOccur(trace, startIndex, endIndex, carrier=const.TMOBILE):
    interfered_states = []
    interfered_indices = []
    for i in range(startIndex, endIndex):
        entry = trace[i]
        if entry.logID == const.SIG_MSG_ID:
            if carrier == const.TMOBILE:
                # FACH_to_DCH promotion
                if entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                   entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                    interfered_states.append(const.FACH_TO_DCH_ID)
                    interfered_indices.append(i)
                # PCH_to_FACH promotion
                elif entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                     entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdate":
                    interfered_states.append(const.PCH_TO_FACH_ID)
                    interfered_indices.append(i)
            elif carrier == const.ATT:
                # Disconnect to DCH
                if entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_REQUEST:
                    interfered_states.append(DISCONNECTED_TO_DCH_ID)
                    interfered_indices.append(i)

    return interfered_states, interfered_indices

# Check whether there exist inaccurate RRC state of IP packet based on 
# RRC state transition messages excluding RRC state transition period
#
# Output:
# 1. A map from inaccurate IP packet to desired RRC state
#    Key: IP packet entry
#    Value: (desired RRC state, time to the previous closing state)
def findInaccurateRRCPackets(trace, carrier=const.TMOBILE, network_type=const.WCDMA):
    privCtrlMSG = None
    expectedRRCID = None
    inTransition = False
    inaccurateMap = {}
    DEL = "\n"    
    
    if INACCURATE_TRANSITION_DEBUG:
        print "%" * 80

    for entry in trace:
        # 3G network
        if network_type == const.WCDMA:
            if entry.logID == const.SIG_MSG_ID:
                # T-Mobile
                if carrier == const.TMOBILE:
                    if INACCURATE_TRANSITION_DEBUG:
                        print "^.^"*10
                        line = str(entry.sig_msg) + DEL
                        if privCtrlMSG != None:
                            line += str(privCtrlMSG.sig_msg) + DEL
                        else:
                            line += "privCtrl is None;" + DEL
                        line += "Expected RRC is " + str(expectedRRCID) + DEL
                        line += "isInTransition is " + str(inTransition) + DEL
                        print line

                    # end of transition
                    # FACH -> PCH
                    if (entry.sig_msg["ch_type"] == "UL_DCCH" and \
                        entry.sig_msg["msg"]["type"] == const.MSG_PHY_CH_RECONFIG_COMPLETE) or \
                        (entry.sig_msg["ch_type"] == "DL_DCCH" and \
                         entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP_CONFIRM and \
                         entry.sig_msg["msg"]["rrc_indicator"] == const.PCH_ID):
                        inTransition = False
                        expectedRRCID = const.PCH_ID
                        privCtrlMSG = entry
                        continue
                    # PCH -> FACH
                    if (entry.sig_msg["ch_type"] == "DL_DCCH" and \
                        (entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP_CONFIRM and \
                         entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID)):
                        inTransition = False
                        expectedRRCID = const.FACH_ID
                        privCtrlMSG = entry
                        continue
                    # DCH -> FACH or FACH -> DCH (Notice that expected RRC state has
                    # been assigned eariler)
                    if (entry.sig_msg["ch_type"] == "UL_DCCH" and \
                        entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG_COMPLETE):
                        inTransition = False
                        privCtrlMSG = entry
                        continue
                    # begin of the state transition
                    if (entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       (entry.sig_msg["msg"]["type"] == const.MSG_PHY_CH_RECONFIG or \
                        entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG) or \
                       (entry.sig_msg["ch_type"] == "UL_CCCH" and \
                        entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP)):
                        inTransition = True
                        expectedRRCID = entry.sig_msg["msg"]["rrc_indicator"]
                        continue
                # AT&T
                elif carrier == const.ATT:
                    pass
        # judge whether current IP packet has been assigned the correct RRC state message
        if entry.logID == const.PROTOCOL_ID:
            if INACCURATE_TRANSITION_DEBUG:
                print "==+"*10
                line = str(entry.sig_msg) + DEL
                if privCtrlMSG != None:
                    line += str(privCtrlMSG.sig_msg) + DEL
                else:
                    line += "privCtrl is None;" + DEL
                line += "Expected RRC is " + str(expectedRRCID) + DEL
                line += "isInTransition is " + str(inTransition) + DEL
                print line

            if inTransition == False and \
               privCtrlMSG != None and \
               expectedRRCID != None:
                # disregard the case of not connecting
                if expectedRRCID != entry.rrcID and entry.rrcID in const.RRC_MAP.keys():
                    inaccurateMap[entry] = {}
                    inaccurateMap[entry]["rrc"] = expectedRRCID
                    inaccurateMap[entry]["time_diff"] = entry.timestamp - privCtrlMSG.timestamp

    return inaccurateMap

# Find the next Radio Bearer Reconfiguration complete entry
def findNextRadioBearerConfiguration(entryList, curIndex):
    MAX_SIG_TIME = 5
    start_time = entryList[curIndex].timestamp
    for i in range(curIndex, len(entryList)):
        entry = entryList[i]
        if entry.logID == const.SIG_MSG_ID and \
           entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
           entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfigurationComplete":
            return i
        if entry.timestamp - start_time > MAX_SIG_TIME:
            return None
    return None
