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
import retxWorker as rw
import Util as util
import validateWorker as vw

RRC_STATE_TRANSITION_DEBUG = False

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
# For mannual insepection
# 10. UDP packet timestamp
# 11. First mapped RLC PDU timestamp
# 12. Last mapped RLC PDU timestamp

def abnormal_rrc_fach_analysis(entryList, server_ip, network_type):
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

    GRANULARITY = 0.5   # assume the granularity of inter-packet timing is 0.5s
    DEL = "\t"
    print "Inter_packet_time" + DEL + \
          "Transmission_delay" + DEL + \
          "Normalized_transmission_delay" + DEL + \
          "OTA_RTT" + DEL + \
          "RLC_retx_ratio" + DEL + \
          "RLC_retx_count" + DEL + \
          "RSCP" + DEL + \
          "ECIO" + DEL + \
          "PRACH_Reset" + DEL + \
          "PRACH_Done" + DEL + \
          "UDP_timestamp" + DEL + \
          "First_Mapped_RLC_timestamp" + DEL + \
          "Last_Mapped_RLC_timestamp"

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
                                # reset everything all the time
                                priv_inter_packet_time = cur_inter_packet_time
                                priv_output_result = cur_output_result
                        else:
                            print >> sys.stderr, "No polling bit ERROR: not confident about \
                                     first hop latency estimation for " + str(inject_num_list)
                            continue
                    else:
                        print >> sys.stderr, "Uniqueness Analysis ERROR: not unique chain for " + str(inject_num_list)
                        continue
                else:
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
def rrc_state_transition_analysis(entryList, client_ip, network_type, direction):
    # statistics summarize the occurance of each state
    rrc_occurance_map = util.gen_RRC_state_count_map()

    print >> sys.stderr, "Finish RRC state count ..."

    # determine the network type
    log_of_interest_id = util.get_logID_of_interest(network_type, direction)

    # Label each IP packet with its corresponding RRC state
    (pktRRCMap, dummy) = label_RRC_state_for_IP_packets(entryList)

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
    print "RRC_state" + DEL + \
          "TCP_RTT" + DEL + \
          "Transmission_delay" + DEL + \
          "Normalized_transmission_delay" + DEL + \
          "OTA_RTT" + DEL + \
          "RLC_retx_ratio" + DEL + \
          "RLC_retx_count" + DEL + \
          "RSCP" + DEL + \
          "ECIO" + DEL + \
          "UDP_timestamp" + DEL + \
          "First_Mapped_RLC_timestamp" + DEL + \
          "Last_Mapped_RLC_timestamp"
    
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
                        print cur_output_result
                        # increment that RRC state's count
                        rrc_occurance_map[pktRRCMap[entry]] += 1.0
                    else:
                        if entry in pktRRCMap:
                            print >> sys.stderr, "TCP RTT estimation failed ERROR at " + util.convert_ts_in_human(entry.timestamp) \
                                                 + " with " + const.RRC_MAP[pktRRCMap[entry]]
                        continue
                else:
                    if entry in pktRRCMap:
                        print >> sys.stderr, "Uniqueness Analysis ERROR at " + util.convert_ts_in_human(entry.timestamp) \
                                             + " with " + const.RRC_MAP[pktRRCMap[entry]]
                    continue
            else:
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
############################# Helper Function ##############################
############################################################################
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
    countMap = util.count_prach_aich_status(entryList, mapped_RLCs[0][-1], mapped_RLCs[-1][-1])
    cur_output_result += str(countMap[const.PRACH_ABORT]) + DEL
    cur_output_result += str(countMap[const.PRACH_DONE]) + DEL

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
def label_RRC_state_for_IP_packets(entryList):
    pktRRCMap = {}
    privPacket = None
    rrc_trans_timer_map = util.gen_RRC_trans_state_list_map()

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
            # FACH -> PCH (case 1)
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfiguration":
                rrc_transit_state_pkt_buffer = []
                rrc_trans_begin_time = entry.timestamp
                continue
            # reset FACH -> PCH (case 1)
            if rrc_transit_state_pkt_buffer != None and \
               entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "physicalChannelReconfigurationComplete":
                util.add_multiple_key_same_value_to_map(pktRRCMap, rrc_transit_state_pkt_buffer, const.FACH_TO_PCH_ID)
                if rrc_trans_begin_time != None:
                    rrc_trans_timer_map[const.FACH_TO_PCH_ID].append(entry.timestamp - rrc_trans_begin_time)
                    rrc_trans_begin_time = None
                rrc_transit_state_pkt_buffer = None
                continue
            # FACH -> PCH (case 2)
            if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdate":
                rrc_transit_state_pkt_buffer = []
                rrc_trans_begin_time = entry.timestamp
                continue
            # reset FACH -> PCH (case 2)
            if rrc_transit_state_pkt_buffer != None and \
               entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdateConfirm" and \
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
               entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "cellUpdateConfirm" and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.PCH_ID:
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
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfiguration" and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                rrc_transit_state_pkt_buffer = []
                rrc_transit_state = const.FACH_TO_DCH_ID
                rrc_trans_begin_time = entry.timestamp
                continue
            # reset FACH -> DCH & DCH -> FACH
            if rrc_transit_state != None and rrc_transit_state_pkt_buffer != None and \
               entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfigurationComplete":
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
               entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == "radioBearerReconfiguration" and \
               entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                rrc_transit_state_pkt_buffer = []
                rrc_transit_state = const.DCH_TO_FACH_ID
                rrc_trans_begin_time = entry.timestamp
                continue
        elif entry.logID == const.PROTOCOL_ID and \
             entry.rrcID != None and \
             entry.ip["tlp_id"] == const.TCP_ID:
            if rrc_transit_state_pkt_buffer != None and rrc_transit_state != None:
                rrc_transit_state_pkt_buffer.append(entry)
            else:
                pktRRCMap[entry] = entry.rrcID
   

    return pktRRCMap, rrc_trans_timer_map

