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

############################################################################
############################### RRC States #################################
############################################################################
# Root cause analysis for the abnormal state information (injected UDP uplink WCDMA)
# Only the last UDP trial packet is instrumented
#
# Output the following column
# 1. Inter-packet timing (s)
# 2. Transmission Delay (ms)
# 3. OTA Delay (ms)
# 4. RLC Retransmission Ratio
# 5. RLC Retransmission Count
# 6. RSCP
# 7. ECIO
# For mannual insepection
# 8. UDP packet timestamp
# 9. First mapped RLC PDU timestamp
# 10. Last mapped RLC PDU timestamp
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
          "OTA_RTT" + DEL + \
          "RLC_retx_ratio" + DEL + \
          "RLC_retx_count" + DEL + \
          "RSCP" + DEL + \
          "ECIO" + DEL + \
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
                            cur_output_result += gen_line_of_root_cause_info(entry, mapped_RLCs, RLCMap, log_of_interest_id, DEL)

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
# 3. Transmission Delay (ms)
# 4. OTA Delay (ms)
# 5. RLC Retransmission Ratio
# 6. RLC Retransmission Count
# 7. RSCP
# 8. ECIO
# For mannual insepection
# 9. UDP packet timestamp
# 10. First mapped RLC PDU timestamp
# 11. Last mapped RLC PDU timestamp
def rrc_state_transition_analysis(entryList, client_ip, network_type, direction):
    # determine the network type
    log_of_interest_id = util.get_logID_of_interest(network_type, direction)

    # Label each IP packet with its corresponding RRC state
    pktRRCMap = label_RRC_state_for_IP_packets(entryList)

    # Assign TCP RTT
    dw.calc_tcp_rtt(entryList, client_ip)
    # Uniqueness analysis
    non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(entryList, log_of_interest_id)
    # RLC retransmission analysis
    [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(entryList, detail="simple")

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
          "OTA_RTT" + DEL + \
          "RLC_retx_ratio" + DEL + \
          "RLC_retx_count" + DEL + \
          "RSCP" + DEL + \
          "ECIO" + DEL + \
          "UDP_timestamp" + DEL + \
          "First_Mapped_RLC_timestamp" + DEL + \
          "Last_Mapped_RLC_timestamp"

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.TCP_ID:
            mapped_RLCs = mapped_sn = None
            if direction.lower() == "up" and entry.ip["src_ip"] == client_ip:
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
            elif direction.lower() == "down" and entry.ip["dst_ip"] == client_ip:
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(entryList, i, log_of_interest_id)
            if mapped_RLCs:
                if vw.is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                    if entry.rtt["tcp"] and entry in pktRRCMap:
                        cur_output_result = str(const.RRC_MAP[pktRRCMap[entry]]) + DEL + \
                                            str(entry.rtt["tcp"]) + DEL
                        cur_output_result += gen_line_of_root_cause_info(entry, mapped_RLCs, RLCMap, log_of_interest_id, DEL)
                        print cur_output_result
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
# 1. Transmission Delay (ms)
# 2. OTA Delay (ms)
# 3. RLC Retransmission Ratio
# 4. RLC Retransmission Count
# 5. RSCP
# 6. ECIO
# For mannual insepection
# 7. UDP packet timestamp
# 8. First mapped RLC PDU timestamp
# 9. Last mapped RLC PDU timestamp
def gen_line_of_root_cause_info(entry, mapped_RLCs, RLCMap, log_of_interest_id, DEL):
    cur_output_result = ""
    # First-hop latency                            
    transmission_delay, rlc_rtt_list = dw.calc_first_hop_latency(mapped_RLCs)
    cur_output_result += str(transmission_delay * 1000) + DEL
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
#
def label_RRC_state_for_IP_packets(entryList):
    pktRRCMap = {}
    privPacket = None

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

    return pktRRCMap

