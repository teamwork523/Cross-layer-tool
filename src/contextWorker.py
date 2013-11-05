#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/10/2013
This file contains all the functions related to context information
"""

import os, sys, re
import const
import QCATEntry as qe
import PrintWrapper as pw
import Util as util

DEBUG = False
CUR_DEBUG = False
ENABLE_SP_RRC_STATE = False

########## RRC ##########
# Map RRC state to each entries
# Also include other special ID for state promotion
#def assignRRCState(entries, ptof, ftod):
def assignRRCState(entries):
    mostRecentRRCID = None
    privEntries = []
    for entry in entries:
        if entry.logID == const.RRC_ID:
            # Trace back and assign special ID
            if ENABLE_SP_RRC_STATE:
                if entry.rrcID == const.DCH_ID and mostRecentRRCID == const.FACH_ID \
                   and privEntries:
                    assignPrivEntryRRC(privEntries, const.FACH_TO_DCH_ID, entry.timestamp)
                if entry.rrcID == const.FACH_ID and mostRecentRRCID == const.PCH_ID \
                   and privEntries:
                    assignPrivEntryRRC(privEntries, const.PCH_TO_FACH_ID, entry.timestamp)
                privEntries = []
            mostRecentRRCID = entry.rrcID
        else:
            if entry.rrcID == None and mostRecentRRCID != None:
                entry.rrcID = mostRecentRRCID
                if ENABLE_SP_RRC_STATE:
                    privEntries.append(entry)
            
# Helper function to assign special RRC state
#def assignPrivEntryRRC(privEntries, rrc_state_id, rrc_state_timestamp, timer):
def assignPrivEntryRRC(privEntries, rrc_state_id, rrc_state_timestamp):
    # Make sure you have the timer in the constant field
    # timer = const.TIMER[rrc_state_id]
    # TODO: delete after tunning
    #if CUR_DEBUG:
        #print timer
    #if not timer:
    timer = const.TIMER[rrc_state_id]
    # assign new id
    if DEBUG:
        print "#" * 40
    for entry in privEntries[::-1]:
        if entry.logID == const.PROTOCOL_ID or \
           entry.logID == const.UL_PDU_ID or \
           entry.logID == const.DL_PDU_ID:
            if entry.timestamp + timer >= rrc_state_timestamp:
                if DEBUG:
                    print "Prvious RRC:"
                    print pw.printEntry(entry)
                entry.rrcID = rrc_state_id
                if DEBUG:
                    print "Current RRC:"
                    print pw.printEntry(entry)

########## EUL ##########
# assign EUL entry information, i.e. bit rate, buffer size
def assignEULState(entries):
    mostRecentRC = None
    mostRecentED = None
    mostRecentSpeed = None
    # Sampling first, then log => bottom up approach
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

# Build a map between timeseries and retransmission count for a specific time
# Notice that it counts the retransmission based on timestamp instead of TS
# @input: burstDuration means once there is a RLC retransmission
#         then group the following burstDuration seconds retx count together
# @return: {ts1:(RSCP, retxCount), ts2:(RSCP, retxCount), ...}
def buildRetxCountvsRSCP_timebased(entries, burstDuration, logID):
    preTS = None
    tsMap = {}
    for entry in entries:
        if entry.sig["RSCP"]:
            retxMap = None
            if entry.logID == logID == const.UL_PDU_ID:
                retxMap = entry.retx["ul"]
            elif entry.logID == logID == const.DL_PDU_ID:
                retxMap = entry.retx["dl"]
            else:
                continue
            retxCount = sum([len(i) for i in retxMap.values()])
            if retxCount > 0:
                if not preTS or \
                   (preTS and preTS + burstDuration < entry.timestamp):
                    # either haven't been 
                    preTS = entry.timestamp
                    tsMap[preTS] = [retxCount, util.medianValue(entry.sig["RSCP"]), util.medianValue(entry.sig["ECIO"])]
                else:
                    tsMap[preTS][0] += retxCount

    return tsMap

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

############## RLC Configuration ##############
# assign previous configurations
def assignPrivConfiguration (entries, logID):
    privConfig = None
    for entry in entries:
        if logID == entry.logID:
            if logID == const.DL_CONFIG_PDU_ID and entry.dl_config["chan"] != None:
                privConfig = entry.dl_config
            elif logID == const.UL_CONFIG_PDU_ID and entry.ul_config["chan"] != None:
                privConfig = entry.ul_config
        else:
            if logID == const.DL_CONFIG_PDU_ID and not entry.dl_config["chan"] and privConfig:
                entry.dl_config = privConfig
            elif logID == const.UL_CONFIG_PDU_ID and not entry.ul_config["chan"] and privConfig:
                entry.ul_config = privConfig


#####################################
########## Helper ###################
#####################################
# filter entries based on input id list
def extractEntriesOfInterest(entries, ids_of_interest):
    new_entries = []
    for entry in entries:
        if entry.logID in ids_of_interest:
            new_entries.append(entry)
    return new_entries
