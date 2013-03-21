#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/20/2013

Most valuable work
"""
import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
import PrintWrapper as pw
from datetime import datetime

DEBUG = True
CUR_DEBUG = False

############################################################################
################## Cross Layer Based on RLC Layer ##########################
############################################################################
# Map RLC PDUs with a given TCP packet
# Basic idea is to track the first byte information from RLC
# and incrementally map with the existing TCP data
# until three conditions:
# 1. We match until we hit a LI PDU
# 2. We run out of current payload size
# 3. Exceeding a build-in limit
# @ASSUME: No filtering on entries, since IP packets could be sagmented
# @input: list of entries, index of the TCP packet in the list, entry logID,
#         index_hint is useful if you know the starting index in the entry
# @output: a sequence of RLC entries that maps with the current TCP packet
#          [(entry1, index1), (entry2, index2), ...]
def mapRLCtoTCP(entries, tcp_index, logID, hint_index = -1):
    # search for the entires IP packets
    tcp_payload = findEntireIPPacket(entries, tcp_index)
    if DEBUG:
        print "#" * 40
        print "Index is %d" % tcp_index
        pw.printEntry(entries[tcp_index])
        print "First ten bytes: %s" % tcp_payload[:10]
        print "Last ten bytes: %s" % tcp_payload[-10:]
    tcp_len = entries[tcp_index].ip["total_len"]
    # tracking which byte has been matched in the TCP payload
    cur_match_index = 0
    max_reachable_index = min(len(entries), tcp_index + const.MAX_ENTRIES_LIST)
    return_entries = []
    
    # default starting point is at the tcp entry
    start_index = tcp_index
    if hint_index != -1:
        start_index = max(hint_index, tcp_index)
        # start_index = hint_index

    for i in range(start_index, max_reachable_index):
        cur_header = None
        find_match = False
        # make sure the RLC entry is a Data PDU entry
        if entries[i].logID == logID == const.UL_PDU_ID and entries[i].ul_pdu[0]["sn"]:
            cur_header = entries[i].ul_pdu[0]["header"]
        elif entries[i].logID == logID == const.DL_PDU_ID and entries[i].dl_pdu[0]["sn"]:
            cur_header = entries[i].dl_pdu[0]["header"]
        else:
            continue

        for j in range(len(cur_header)):
            if isDataMatch(cur_header[j]["data"], tcp_payload, cur_match_index):
                find_match = True
                if cur_header[j].has_key("li"):
                    # get first li result
                    cur_match_index += cur_header[j]["li"][0]
                else:
                    cur_match_index += cur_header[j]["len"]
            else:
                find_match = False
                # if contain data then append the rest of payload
                if cur_header[j].has_key("li") and cur_header[j]["data"]:
                    cur_match_index = cur_header[j]["len"] - cur_header[j]["li"][0]
                # Exceptional case: indicate that last entry, but not padding data
                # i.e. 2 li + 2 e + no data
                elif cur_header[j].has_key("li") and not cur_header[j]["data"]:
                    cur_match_index += cur_header[j]["li"][0]
                else:
                    cur_match_index = 0
            if CUR_DEBUG:
                print "&" * 60
                print cur_header[j]
                print "cur_header position %d" % j
                print "Does match find? %s" % find_match
                print "TCP matched index %d" % cur_match_index
            # Check if the length matches the TCP header length
            if cur_match_index == tcp_len:
                return_entries.append((entries[i], i))
                if DEBUG:
                    print "@" * 50
                    print "!!!!!! Great!!!!!! Find match at index %d" % (i)
                    pw.printRLCEntry(return_entries[0][0], "up")
                    print return_entries
                return return_entries
            # handle the case where data mismatch at the length indicator entry
            elif cur_header[j].has_key("li") and not cur_header[j]["data"]:
                cur_match_index = 0
            elif cur_header[j].has_key("li") and cur_header[j]["data"]:
                cur_match_index = cur_header[j]["len"] - cur_header[j]["li"][0]

        if find_match:
            return_entries.append((entries[i], i))
        else:
            return_entries = []
        if CUR_DEBUG:
            print "+++" * 5
            print "At index %d" % i

    if CUR_DEBUG:
        print return_entries
    return False

# match the existing data with payload
def isDataMatch(dataList, payload, matching_index):
    # handle PDU no PDU entry no payload case
    if not dataList and payload:
        return False
        #return True
    payloadLen = len(payload)
    for dataIndex in range(len(dataList)):
        if matching_index + dataIndex >= payloadLen or \
           dataList[dataIndex] != payload[matching_index + dataIndex]:
            return False
    return True

# Find the entire IP packets 
def findEntireIPPacket (entries, index):
    cur_custom_seq_num = entries[index].custom_header["seq_num"]
    payload = entries[index].hex_dump["payload"][const.Payload_Header_Len:]

    # if current IP is already the last segment, then return directly
    if entries[index].custom_header["final_seg"]:
        return payload 

    index += 1
    entryLen = len(entries)
    while (entries[index].logID != const.PROTOCOL_ID) or \
          (entries[index].logID == const.PROTOCOL_ID and entries[index].custom_header["seq_num"] == cur_custom_seq_num and \
          not entries[index].custom_header["final_seg"] and index < entryLen):
        if entries[index].logID != const.PROTOCOL_ID:
            index += 1
            continue
        payload += entries[index].hex_dump["payload"][const.Payload_Header_Len:]
        index += 1
    
    # include the last segment as payload
    if entries[index].custom_header["final_seg"]:
        payload += entries[index].hex_dump["payload"][const.Payload_Header_Len:]

    return payload

############################################################################
############## Statistics Generated from Cross Layer Mapping ###############
############################################################################
# We want to know the number of RLC layer retransmission between the two TCP
# retransmission 
# @input: retxList is optional if you just want to test the combination of Retx
#         RLC entries
# @return: 
# 1. map between RLC sequence number and retransmission count
# 2. map between timestamp and retransmission bytes
# 3. a list of retransmission entries
# def RLCRetxMapsForInterval (entries, start_index, end_index, logID):
def RLCRetxMapsForInterval (entries, start_index, end_index, logID, retxRLCEntries = None):
    if start_index < 0 or end_index < 0 or start_index >= len(entries) or \
       end_index >= len(entries):
        return None
    # {sn1: # of retx, sn2: # of retx, ...}    
    RetxCountSNMap = {}
    # {ts1: # of retx byte, ts2: # of retx byte}
    RetxByteTimeMap = {}
    # A list of retransmission entries
    RetxEntriesList = []

    listRange = range(start_index, end_index + 1)
    if retxRLCEntries:
        listRange = [i[1] for i in retxRLCEntries]
    for i in listRange:
        PDU_SNs = None
        if entries[i].logID == logID == const.UL_PDU_ID:
            PDU = entries[i].ul_pdu[0]
        elif entries[i].logID == logID == const.DL_PDU_ID:
            PDU = entries[i].dl_pdu[0]
        else:
            continue
        
        for sn_index in range(len(PDU["sn"])):
            if RetxCountSNMap.has_key(PDU["sn"][sn_index]):
                RetxCountSNMap[PDU["sn"][sn_index]] += 1
                if RetxByteTimeMap.has_key(entries[i].timestamp):
                    RetxByteTimeMap[entries[i].timestamp] += PDU["size"][sn_index]
                else:
                    RetxByteTimeMap[entries[i].timestamp] = PDU["size"][sn_index]
                if entries[i] not in RetxEntriesList:
                    RetxEntriesList.append(entries[i])
            else:
                RetxCountSNMap[PDU["sn"][sn_index]] = 0

    return (RetxCountSNMap, RetxByteTimeMap, RetxEntriesList)
