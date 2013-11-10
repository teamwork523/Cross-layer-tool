#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   11/10/2013

Validation for RRC inference, feasibility of cross layer mapping and etc.
"""

import os, sys, time
import const

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
def check_mapping_feasibility_uniqueness(entryList, direction, network_type="wcdma"):
    # key is data chain, value is the total number of appearance
    uniqueCount = {}
    curKey = ""

    # determine the log of interest
    log_of_interest_id = None
    # TODO: add LTE if necessary
    if network_type.lower() == "wcdma":
        if direction.lower() == "up":
            log_of_interest_id = const.UL_PDU_ID
        else:
            log_of_interest_id = const.DL_PDU_ID

    for entry in entryList:
        if entry.logID == log_of_interest_id:
            pdu = find_pdu_based_on_log_id(entry, log_of_interest_id)
            for header in pdu["header"]:
                if header["he"] == 2 or header["li"][-1] == 127:
                    if curKey in uniqueCount:
                        uniqueCount[curKey] += 1
                    else:
                        uniqueCount[curKey] = 1
                    # reset the key
                    curKey = ""
                else:
                    curKey += "".join(header["data"])
    
    # count the key appear twice or more
    dupCount = float(len([x for x in uniqueCount.values if x > 1]))
    totalCount = float(len(uniqueCount.keys()))
    
    print "Duplicat percentage %f / %f = %f" % (dupCount, totalCount, dupCount / totalCount)


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
# return the corresponding pdu entry based on id
def find_pdu_based_on_log_id(entry, log_id):
    # TODO: add LTE if necessary
    if log_id == const.UL_PDU_ID:
        return entry.ul_pdu[0]
    elif log_id == const.DL_PDU_ID:
        return entry.dl_pdu[0]
        


