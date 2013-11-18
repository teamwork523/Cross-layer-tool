#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   11/10/2013

Validation for RRC inference, feasibility of cross layer mapping and etc.
"""

import os, sys, time
import const
import crossLayerWorker as clw
import Util as util

############################################################################
############################# RRC Inference ################################
############################################################################
# Validate RRC inference algorithm
# Output:
# timestamp \t RRC state
def rrc_inference_validation(entryList):
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID:
            print str(entry.timestamp) + "\t" + str(entry.rrcID)

############################################################################
##################### Cross-layer feasibility ##############################
############################################################################
# Examine the uniqueness of the RLC layer PDU "chain" mapping
# Two possible termination of the chain (WCDMA uplink)
# 1. HE = 2
# 2. The last LI (most likely the second is 127)
def check_mapping_feasibility_uniqueness(entryList, client_ip, direction, network_type="wcdma"):
    # determine the log of interest
    log_of_interest_id = None
    
    # Determine the log of interest we wanna focus on
    log_of_interest_id = util.get_logID_of_interest(network_type, direction)

    non_unique_rlc_tuples, uniqueCount = uniqueness_analysis(entryList, log_of_interest_id)

    print "Non unique RLC tuple length is %d" % (len(non_unique_rlc_tuples))

    # count the key appear twice or more
    dupChainCount = 0.0
    dupPDUCount = 0.0
    totalChainCount = 0.0
    totalPDUCount = 0.0
    DEL = ","
    sortedDuplicateCount = {}   # key is count, value is the chain bytes

    for key, val in uniqueCount.items():
        totalPDUCount += len(key) / 4 * val
        totalChainCount += val
        if val > 1:
            dupPDUCount += len(key) / 4 * val
            dupChainCount += val
            sortedDuplicateCount[val] = key

    # cross-layer analysis to check the untrusted mapping for transport layer
    transport_layer_total_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}    
    valid_transport_layer_mapping_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}
    valid_RLC_first_hop_esimation_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID:
            # Exclude TCP ACK without payload and TSL without payload
            """
            if entry.ip["tlp_id"] == const.TCP_ID and\
               (entry.ip["total_len"] == 40 or \
                entry.ip["total_len"] == 52 or \
                entry.ip["total_len"] == 83):
                continue
            """
            if (log_of_interest_id == const.UL_PDU_ID and \
               entry.ip["src_ip"] == client_ip) or \
               (log_of_interest_id == const.DL_PDU_ID and \
               entry.ip["dst_ip"] == client_ip):
                if entry.ip["tlp_id"] in transport_layer_total_count:
                    transport_layer_total_count[entry.ip["tlp_id"]] += 1
                mapped_RLCs, mapped_sn = clw.map_SDU_to_PDU(entryList, i, log_of_interest_id)
                if mapped_RLCs:
                    if is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                        if entry.ip["tlp_id"] in valid_transport_layer_mapping_count:
                            valid_transport_layer_mapping_count[entry.ip["tlp_id"]] += 1
                    if is_valid_first_hop_latency_estimation(mapped_RLCs, mapped_sn, log_of_interest_id):
                        if entry.ip["tlp_id"] in valid_RLC_first_hop_esimation_count:
                            valid_RLC_first_hop_esimation_count[entry.ip["tlp_id"]] += 1                   

    # output results
    print "Chain_occurance" + DEL + "Chain_PDU_length" + DEL + "Chain_value"

    for sortedKey in sorted(sortedDuplicateCount.keys(), reverse=True):
        print str(sortedKey) + DEL + \
              str(len(sortedDuplicateCount[sortedKey]) / 4) + DEL + \
              str(sortedDuplicateCount[sortedKey])
    
    print "$" * 80
    print "Unique Chain ratio %f / %f = %f" % (totalChainCount - dupChainCount, totalChainCount, 1 - dupChainCount / totalChainCount)
    print "Unique PDUs ratio %f / %f = %f" % (totalPDUCount - dupPDUCount, totalPDUCount, 1 - dupPDUCount / totalPDUCount)
    print "Unique TCP ratio %f / %f = %f" % (valid_transport_layer_mapping_count[const.TCP_ID], \
                                             transport_layer_total_count[const.TCP_ID], \
                                             valid_transport_layer_mapping_count[const.TCP_ID] / \
                                             transport_layer_total_count[const.TCP_ID])
    print "Unique UDP ratio %f / %f = %f" % (valid_transport_layer_mapping_count[const.UDP_ID], \
                                             transport_layer_total_count[const.UDP_ID], \
                                             valid_transport_layer_mapping_count[const.UDP_ID] / \
                                             transport_layer_total_count[const.UDP_ID])
    print "Valid TCP first hop esitmation ratio %f / %f = %f" % \
                                            (valid_RLC_first_hop_esimation_count[const.TCP_ID], \
                                             transport_layer_total_count[const.TCP_ID], \
                                             valid_RLC_first_hop_esimation_count[const.TCP_ID] / \
                                             transport_layer_total_count[const.TCP_ID])
    print "Valid UDP first hop esitmation ratio %f / %f = %f" % \
                                            (valid_RLC_first_hop_esimation_count[const.UDP_ID], \
                                             transport_layer_total_count[const.UDP_ID], \
                                             valid_RLC_first_hop_esimation_count[const.UDP_ID] / \
                                             transport_layer_total_count[const.UDP_ID])


# compare total bytes and total number of packet in both uplink and downlink
# Output: statistics about the bytes and packet/PDU counts 
def check_mapping_feasibility_use_bytes(mainEntryList, client_ip):
    uplink_stat = {"ip": {"bytes":0.0, "counts":0.0}, "rlc": {"bytes":0.0, "counts":0.0}}
    downlink_stat = {"ip": {"bytes":0.0, "counts":0.0}, "rlc_flex": {"bytes":0.0, "counts":0.0}, "rlc": {"bytes":0.0, "counts":0.0}}
    
    for entry in mainEntryList:
        if entry.logID == const.PROTOCOL_ID:
            if entry.ip["src_ip"] == client_ip:
                uplink_stat["ip"]["counts"] += 1
                uplink_stat["ip"]["bytes"] += entry.ip["total_len"]
            elif entry.ip["dst_ip"] == client_ip:
                downlink_stat["ip"]["counts"] += 1
                downlink_stat["ip"]["bytes"] += entry.ip["total_len"]
        elif entry.logID == const.UL_PDU_ID:
            for header in entry.ul_pdu[0]["header"]:
                uplink_stat["rlc"]["counts"] += 1
                uplink_stat["rlc"]["bytes"] += header["len"]
        elif entry.logID == const.DL_PDU_ID:
            for header in entry.dl_pdu[0]["header"]:
                downlink_stat["rlc_flex"]["counts"] += 1
                downlink_stat["rlc_flex"]["bytes"] += header["len"]
        elif entry.logID == const.DL_CTRL_PDU_ID:
            for header in entry.dl_pdu[0]["header"]:
                downlink_stat["rlc"]["counts"] += 1
                downlink_stat["rlc"]["bytes"] += header["len"]

    print "$"*80
    print "Uplink Status: "
    print uplink_stat
    print "Bytes diff ratio %f" % (abs(uplink_stat["ip"]["bytes"] - uplink_stat["rlc"]["bytes"]) \
                                   / uplink_stat["ip"]["bytes"])
    print "Count diff ratio %f" % (abs(uplink_stat["ip"]["counts"] - uplink_stat["rlc"]["counts"]) \
                                   / uplink_stat["ip"]["counts"])
    print "@"*80
    print "Downlink Status: "
    print downlink_stat
    print "Flex Bytes diff ratio %f" % (abs(downlink_stat["ip"]["bytes"] - downlink_stat["rlc_flex"]["bytes"]) \
                                   / downlink_stat["ip"]["bytes"])
    print "Bytes diff ratio %f" % (abs(downlink_stat["ip"]["bytes"] - downlink_stat["rlc"]["bytes"]) \
                                   / downlink_stat["ip"]["bytes"])
    print "Flex Count diff ratio %f" % (abs(downlink_stat["ip"]["counts"] - downlink_stat["rlc_flex"]["counts"]) \
                                   / downlink_stat["ip"]["counts"])
    print "Count diff ratio %f" % (abs(downlink_stat["ip"]["counts"] - downlink_stat["rlc"]["counts"]) \
                                   / downlink_stat["ip"]["counts"])

############################################################################
################################# Helper ###################################
############################################################################        
# Valid the uniqueness of the cross-layer mapping
def is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_id, non_unique_rlc_tuples):
    for rlc_pdu in mapped_RLCs:
        entry = rlc_pdu[0]
        pdu = util.find_pdu_based_on_log_id(entry, log_id)
        for sn in pdu["sn"]:
            if (sn in mapped_sn) and \
               ((entry, sn) in non_unique_rlc_tuples):
                return False
    return True

# check whether a polling bit existing for the mapped RLC list
def is_valid_first_hop_latency_estimation(mapped_RLCs, mapped_sn, log_id):
    for rlc_pdu in mapped_RLCs:
        entry = rlc_pdu[0]
        pdu = util.find_pdu_based_on_log_id(entry, log_id)
        for i in range(len(pdu["sn"])):
            sn = pdu["sn"][i]
            if (pdu["header"][i]["p"] != None) and \
               (sn in mapped_sn):
                return True
    return False

# Uniqueness analysis -- filter out the non-unique RLC entries
# Output:
# 1. A set of nonunique RLC tuples with (rlc_entry, sn)
# 2. A map between RLC data chain to the count
def uniqueness_analysis(entryList, log_of_interest_id):
    curKey = ""
    non_unique_rlc_tuples = []
    non_unique_buffer = []
    uniqueCount = {}

    for entry in entryList:
        if entry.logID == log_of_interest_id:
            pdu = util.find_pdu_based_on_log_id(entry, log_of_interest_id)
            for i in range(len(pdu["header"])):
                header = pdu["header"][i]
                sn = pdu["sn"][i]
                if (header.has_key("he") and header["he"] == 2) or (header.has_key("li") and header["li"][-1] == 127):
                    if curKey != "":
                        if curKey in uniqueCount:
                            uniqueCount[curKey] += 1
                            non_unique_rlc_tuples += non_unique_buffer
                            non_unique_buffer = []
                        else:
                            uniqueCount[curKey] = 1
                        # reset the key
                        curKey = ""
                    non_unique_buffer = []
                else:
                    curKey += "".join(header["data"])
                    non_unique_buffer.append((entry, sn))

    return set(non_unique_rlc_tuples), uniqueCount
