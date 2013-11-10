#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   11/10/2013

Validation for RRC inference, feasibility of cross layer mapping and etc.
"""

import os, sys, time
import const

# Validate RRC inference algorithm
# Output:
# timestamp \t RRC state
def rrc_inference_validation(entryList):
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID:
            print str(entry.timestamp) + "\t" + str(entry.rrcID)

# compare total bytes and total number of packet in both uplink and downlink
def check_mapping_feasibility(mainEntryList, client_ip):
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
