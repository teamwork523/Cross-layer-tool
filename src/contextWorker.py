#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/10/2013
This file contains all the functions related to context information
"""

import os, sys, re
import const
import QCATEntry as qe

########## RRC ##########
# Map RRC state to each entries
def assignRRCState(entries):
    mostRecentRRCID = None
    for entry in entries:
        if entry.logID == const.RRC_ID:
            mostRecentRRCID = entry.rrcID
        else:
            if entry.rrcID == None and mostRecentRRCID != None:
                entry.rrcID = mostRecentRRCID

########## EUL ##########
# assign EUL entry information, i.e. bit rate, buffer size
def assignEULState(entries):
    mostRecentRC = None
    mostRecentED = None
    mostRecentSpeed = None
    # need bottom up approach
    entries.reverse()
    for entry in entries:
        if entry.logID == const.EUL_STATS_ID:
            if entry.eul["t2p_ec"] != -1:
                mostRecentRC = entry.eul["t2p_ec"]
            if entry.eul["t2p_ed"] != -1:
                mostRecentED = entry.eul["t2p_ed"]
            if entry.eul["raw_bit_rate"] != 0:
                mostRecentSpeed = entry.eul["raw_bit_rate"]
        else:
            if mostRecentRC != None:
                entry.eul["t2p_ec"] = mostRecentRC
            if mostRecentED != None:
                entry.eul["t2p_ed"] = mostRecentED
            if mostRecentSpeed != None:
                entry.eul["raw_bit_rate"] = mostRecentSpeed
    entries.reverse()

########## Flow information ##########
# Find and label the first entry of the flow
def assignFlowInfo (entries):
    # ACT as a reference to the object -> Able to update directly afterwards
    privTuple = {}
    for entry in entries:
        if entry.logID == const.PROTOCOL_ID:
            if privTuple and not entry.flow:
                # Find the ACK number right and update the 
                if entry.tcp["seq_num"] == privTuple["seq_num"] + 1 and \
                   privTuple["ack_num"] == 0 and \
                   entry.tcp["ACK_FLAG"]:
                    privTuple["ack_num"] = entry.tcp["ack_num"]
                    privTuple["timestamp"] = entry.timestamp
                entry.flow = privTuple
            elif entry.flow:
                privTuple = entry.flow

########## Signal Strength ##########
# Use reselection for signal strength
def assignSignalStrengthValue(entries):
    mostRecentECIO = None
    mostRecentRSCP = None
    for entry in entries:
        if entry.logID == const.SIG_ID:
            if entry.sig["ECIO"]:
                mostRecentECIO = entry.sig["ECIO"]
            else:
                if mostRecentECIO:
                    entry.rssi["ECIO"] = mostRecentECIO
            if entry.sig["RSCP"]:
                mostRecentRSCP = entry.sig["RSCP"]
            else:
                if mostRecentRSCP:
                    entry.sig["RSCP"] = mostRecentRSCP
        else:  
            if mostRecentECIO:
                entry.sig["ECIO"] = mostRecentECIO
            if mostRecentRSCP:
                entry.sig["RSCP"] = mostRecentRSCP

########## Throughput ##########
def calThrouhgput(entries, direction):
    # TODO: use the sequence number to compute the throughput
    for i in entries:
        if i.logID == const.PROTOCOL_ID and i.ip["tlp_id"] == const.TCP_ID and \
           i.flow and i.tcp["ACK_FLAG"] and not i.tcp["SYN_FLAG"]:
            cur_ts = i.timestamp
            # RULES:
            # 1) Uplink
            #    SAME src_ip: use seq_num; NOT SAME use ack_num
            # 2) Downlink
            #    SAME src_ip: use ack_num; NOT SAME use seq_num
            byte = 0
            if direction.lower() == "up":
                if i.ip["src_ip"] == i.flow["src_ip"] and i.ip["dst_ip"] == i.flow["dst_ip"]:
                    byte = i.tcp["seq_num"] - i.flow["seq_num"]
                elif i.ip["src_ip"] == i.flow["dst_ip"] and i.ip["dst_ip"] == i.flow["src_ip"]:
                    byte = i.tcp["ack_num"] - i.flow["seq_num"]
            else:
                if i.ip["src_ip"] == i.flow["src_ip"] and i.ip["dst_ip"] == i.flow["dst_ip"]:
                    byte = i.tcp["ack_num"] - i.flow["ack_num"]
                elif i.ip["src_ip"] == i.flow["dst_ip"] and i.ip["dst_ip"] == i.flow["src_ip"]:
                    byte = i.tcp["seq_num"] - i.flow["ack_num"]                    
            i.throughput = computeThroughput(byte, cur_ts - i.flow["timestamp"])
            """
            print "#" * 40
            print convert_ts_in_human(cur_ts)
            print cur_ts
            print "^^^^^^^^^ Flow info:"
            print i.flow
            print "~~~~~~~TCP:"
            print i.tcp
            print "@@@@@@@ IP: "
            print i.ip
            print "Byte is %f" % (byte)
            print "Time diff is %f" % (cur_ts - i.flow["timestamp"])
            print "Throught is : %d" % (i.throughput) 
            """
