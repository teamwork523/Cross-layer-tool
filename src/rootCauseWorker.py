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
############################# RRC Inference ################################
############################################################################
# Root cause analysis for the abnormal state information (injected UDP uplink WCDMA)
# Only the last UDP trial packet is instrumented
#
# Output the following column
# 1. Inter-packet timing (s)
# 2.1 Transmission Delay (ms)
# 2.2 OTA Delay (ms)
# 3. RLC Retransmission Ratio
# 4. RLC Retransmission Count
# 5. RSCP
# 6. ECIO
# For mannual insepection
# 7. UDP packet timestamp
# 8. First mapped RLC PDU timestamp
# 9. Last mapped RLC PDU timestamp
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
    # TODO: assume always use Uplink retx map
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

                            # Compare with previous round
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
        
############################################################################
############################# Helper Function ##############################
############################################################################
# Extract the injected number with format xx:yy;
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

