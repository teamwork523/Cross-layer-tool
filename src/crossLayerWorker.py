#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/20/2013

Procise one-to-one mapping between TCP packet and RLC PDUs
"""
import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
import PrintWrapper as pw
import Util as util
from datetime import datetime

DEBUG = False
DETAIL_DEBUG = False
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
#          All the sequence number must increase by one each time!!!
# @input: list of entries, index of the TCP packet in the list, entry logID,
#         index_hint is useful if you know the starting index in the entry
# @output: 
#       1. a sequence of RLC entries that maps with the current TCP packet
#          [(entry1, index1), (entry2, index2), ...]
#       2. a list of corresponding sequnce number

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
    
    # return variable
    return_entries = []
    mapped_seq_num_list = []
    
    # default starting point is at the tcp entry
    start_index = tcp_index
    if hint_index != -1:
        start_index = max(hint_index, tcp_index)
        # start_index = hint_index
    if DEBUG:
        print "Start_index at %d" % start_index
        pw.printRLCEntry(entries[start_index], "up")
    # A sequence number tracker to make sure it compare with the next sequnece number
    priv_seq_num = None

    for i in range(start_index, max_reachable_index):
        cur_header = None
        cur_seq_num_li = None
        find_match = False
        # make sure the RLC entry is a Data PDU entry
        if entries[i].logID == logID == const.UL_PDU_ID and entries[i].ul_pdu[0]["sn"]:
            cur_header = entries[i].ul_pdu[0]["header"]
            cur_seq_num_li = entries[i].ul_pdu[0]["sn"]
            if not priv_seq_num:
                priv_seq_num = (cur_seq_num_li[0] - 1) % const.MAX_RLC_UL_SEQ_NUM
        elif entries[i].logID == logID == const.DL_PDU_ID and entries[i].dl_pdu[0]["sn"]:
            cur_header = entries[i].dl_pdu[0]["header"]
            cur_seq_num_li = entries[i].dl_pdu[0]["sn"]
            if not priv_seq_num:
                priv_seq_num = (cur_seq_num_li[0] - 1) % const.MAX_RLC_UL_SEQ_NUM
        else:
            continue

        for j in range(len(cur_header)):
            # a lossy check because of RLC packet loss
            if cur_seq_num_li[j] % const.MAX_RLC_UL_SEQ_NUM < (priv_seq_num + 1) % const.MAX_RLC_UL_SEQ_NUM:
                continue
            else:
                priv_seq_num = cur_seq_num_li[j]

            if isDataMatch(cur_header[j]["data"], tcp_payload, cur_match_index):
                find_match = True
                if cur_header[j].has_key("li"):
                    # get first li result
                    cur_match_index += cur_header[j]["li"][0]
                else:
                    cur_match_index += cur_header[j]["len"]
                # find a match then append to return seq num list
                mapped_seq_num_list.append(cur_seq_num_li[j])
            else:
                find_match = False
                # if contain data then append the rest of payload
                if cur_header[j].has_key("li") and cur_header[j]["data"]:
                    cur_match_index = cur_header[j]["len"] - cur_header[j]["li"][0]
                    mapped_seq_num_list = []
                # Exceptional case: indicate that last entry, but not padding data
                # i.e. 2 li + 2 e + no data
                elif cur_header[j].has_key("li") and not cur_header[j]["data"]:
                    cur_match_index += cur_header[j]["li"][0]
                else:
                    cur_match_index = 0
                    mapped_seq_num_list = []
            if DETAIL_DEBUG:
                print "&" * 60
                print cur_header[j]
                print "cur_header position %d" % j
                print "Does match find? %s" % find_match
                print "TCP matched index %d and total length is %d" % (cur_match_index, tcp_len)
            # Check if the length matches the TCP header length
            if cur_match_index == tcp_len:
                return_entries.append((entries[i], i))
                if DEBUG:
                    print "@" * 50
                    print "!!!!!! Great!!!!!! Find match at index %d" % (i)
                    pw.printRLCEntry(return_entries[0][0], "up")
                    print return_entries
                return (return_entries, mapped_seq_num_list)
            # handle the case where data mismatch at the length indicator entry
            elif cur_header[j].has_key("li") and not cur_header[j]["data"]:
                cur_match_index = 0
            elif cur_header[j].has_key("li") and cur_header[j]["data"]:
                cur_match_index = cur_header[j]["len"] - cur_header[j]["li"][0]

        if find_match:
            return_entries.append((entries[i], i))
        else:
            return_entries = []
        if DETAIL_DEBUG:
            print "+++" * 5
            print "At index %d" % i

    if DETAIL_DEBUG:
        print (return_entries, mapped_seq_num_list)
    return (None, None)

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
# Map all the duplicate sequence for a given RLC entry list
# We define the interval as the original TCP packet mapped RLC and 
# the last retransmitted TCP packet mapped RLC
# @return: 
# 1. map between RLC sequence number and retransmission count
# 2. map between timestamp and retransmission bytes
# 3. a list of retransmission entries
def generateRLCMap (entries, orig_RLC_list, interval, logID):
    pass


# We want to know the number of RLC layer retransmission between the two TCP
# retransmission 
# @input: retxList is optional if you just want to test the combination of Retx
#         RLC entries
# @return: 
# 1. map between timestamp and transmission count
# 2. map between timestamp and transmission bytes
# 3. map between seq num and transmission count
# 4. map between timestamp and entry
# 5. map between seq num and entry
# def RLCTxMaps (entries, start_index, end_index, logID):
def RLCTxMaps (entries, orig_sn_list, logID, interval = (0,0), retxRLCEntries = None):
    start_index, end_index = interval
    if start_index < 0 or end_index < 0 or start_index >= len(entries) or \
       end_index >= len(entries):
        return None
    # Tx Count Map: {ts1: # of transmission, ts2: # of transmission, ...}
    TxCountTimeMap = {}
    # Tx Byte Map: {ts1: # of transmitted byte, ts2: # of transmitted byte}
    TxByteTimeMap = {}
    # SN Count Map: {sn1: # of transmission, sn2: # of transmission}
    TxCountSNMap = dict(zip(orig_sn_list, [0]*len(orig_sn_list)))
    # Time Entry Map: {ts1: correspond entry, ts2: correspond entry}
    TSEntryMap = {}
    # Sequence Number Map: {sn1: correspond entry, sn2: correspond entry}
    SNEntryMap = {}
    # A list of retransmission entries
    # RetxEntriesList = []
    # A set of original list of sequence number
    orig_sn_set = set(orig_sn_list)

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
            if PDU["sn"][sn_index] in orig_sn_set:
                TxCountSNMap[PDU["sn"][sn_index]] += 1
                SNEntryMap[PDU["sn"][sn_index]] = entries[i]
                if TxCountTimeMap.has_key(entries[i].timestamp):
                    TxCountTimeMap[entries[i].timestamp] += 1
                    TxByteTimeMap[entries[i].timestamp] += PDU["size"][sn_index]
                else:
                    TSEntryMap[entries[i].timestamp] = entries[i]
                    TxCountTimeMap[entries[i].timestamp] = 1
                    TxByteTimeMap[entries[i].timestamp] = PDU["size"][sn_index]
                """
                if TxByteTimeMap.has_key(entries[i].timestamp):
                    TxByteTimeMap[entries[i].timestamp] += PDU["size"][sn_index]
                else:
                    TxByteTimeMap[entries[i].timestamp] = PDU["size"][sn_index]
                if entries[i] not in RetxEntriesList:
                    RetxEntriesList.append(entries[i])
                """

    return (TxCountTimeMap, TxCountSNMap, TxByteTimeMap, TSEntryMap, SNEntryMap)

# A wrapper function to combine information between TCP/RLC retx time map and TCP -> RLC map
# Retrun aggregated five maps between TCP and RLC
def TCPAndRLCMapper (QCATEntries, entryIndexMap, retxTimeMap, pduID):
    # top level maps
    # {"TCP": [map1, map2], "RLC": [map1, map2....]} # index between TCP and RLC is one-to-one
    countTimeTopMap = {"TCP":[], "RLC":[]}
    byteTimeTopMap = {"TCP":[], "RLC":[]}
    countSNTopMap = {"TCP": None, "RLC":[]}
    entryTimeTopMap = {"TCP":[], "RLC":[]}
    entrySNTopMap = {"TCP": None, "RLC": []}

    for key in sorted(retxTimeMap.keys()):
        # Three Time based Maps for TCP to find the retransmission value and timestamp
        TCPcountTimeMap = {}
        TCPbyteTimeMap = {}
        TCPentryTimeMap = {}
        
        keyChain = []
        origTCPPacket = retxTimeMap[key][0][0]
        # map with original packet
        mapped_RLCs, orig_mapped_sn = mapRLCtoTCP(QCATEntries, entryIndexMap[origTCPPacket], pduID)
        if not mapped_RLCs:
            if DEBUG:
                print "Fail to find a match for the original TCP packet!!!"
            continue
        
        TCPcountTimeMap[origTCPPacket.timestamp] = 1
        TCPbyteTimeMap[origTCPPacket.timestamp] = origTCPPacket.ip["total_len"]
        TCPentryTimeMap[origTCPPacket.timestamp] = origTCPPacket
 
        if DEBUG:
            print "# of retransmission is %d" % len(retxTimeMap[key][0])
            print "Original TCP mapped Sequnce number is "
            print orig_mapped_sn
        # consider multiple retransmission
        for retxEntry in retxTimeMap[key][0][1:]:
            temp_list, mapped_sn = mapRLCtoTCP(QCATEntries, entryIndexMap[retxEntry], pduID, hint_index = mapped_RLCs[-1][1])
            if temp_list:
                mapped_RLCs += temp_list
                TCPcountTimeMap[retxEntry.timestamp] = 1
                TCPbyteTimeMap[retxEntry.timestamp] = retxEntry.ip["total_len"]
                TCPentryTimeMap[retxEntry.timestamp] = retxEntry
            else:
                if DEBUG:
                    print "NO!!!"
                    print "Try to find the match!!!"
        # Map until the one entry after the last retransmission
        entryAfterLastRetx = retxTimeMap[key][1]
        if entryAfterLastRetx:
            if mapped_RLCs:
                lastMapped_list, mapped_sn = mapRLCtoTCP(QCATEntries, entryIndexMap[entryAfterLastRetx], pduID, hint_index = mapped_RLCs[-1][1])
            else:
                lastMapped_list, mapped_sn = mapRLCtoTCP(QCATEntries, entryIndexMap[entryAfterLastRetx], pduID, hint_index = mapped_RLCs[-1][1])
        # use the first matched RLC as the ending mapping indicator
        if lastMapped_list:
            mapped_RLCs.append(lastMapped_list[0])

        if mapped_RLCs:
            #RLCcountTimeMap, RLCcountSNMap, RLCbyteTimeMap, RLCentryTimeMap, RLCentrySNMap = RLCTxMaps(QCATEntries, mapped_RLCs[0][1], mapped_RLCs[-1][1], pduID, retxRLCEntries = mapped_RLCs)
            #RLCcountTimeMap, RLCcountSNMap, RLCbyteTimeMap, RLCentryTimeMap, RLCentrySNMap = RLCTxMaps(QCATEntries, mapped_RLCs[0][1], mapped_RLCs[-1][1], pduID)
            RLCcountTimeMap, RLCcountSNMap, RLCbyteTimeMap, RLCentryTimeMap, RLCentrySNMap = RLCTxMaps(QCATEntries, orig_mapped_sn, pduID, interval = (mapped_RLCs[0][1], mapped_RLCs[-1][1]))
            #RLCcountTimeMap, RLCcountSNMap, RLCbyteTimeMap, RLCentryTimeMap, RLCentrySNMap = RLCTxMaps(QCATEntries, orig_mapped_sn, pduID, interval = (mapped_RLCs[0][1], mapped_RLCs[-1][1]), retxRLCEntries = mapped_RLCs)
            if DEBUG:
                # pick the maximum number of retransmissions in the map
                print "Retransmission count is %d" % (max(RLCcountSNMap.values() + [0]))
                print RLCcountTimeMap
                print RLCcountSNMap
                print RLCbyteTimeMap
                print RLCentryTimeMap
                print RLCentrySNMap

        countTimeTopMap["TCP"].append(TCPcountTimeMap)
        byteTimeTopMap["TCP"].append(TCPbyteTimeMap)
        entryTimeTopMap["TCP"].append(TCPentryTimeMap)
        if DETAIL_DEBUG:
            print "Current RLCcountTimeMap is"
            print RLCcountTimeMap
        countTimeTopMap["RLC"].append(RLCcountTimeMap)
        byteTimeTopMap["RLC"].append(RLCbyteTimeMap)
        countSNTopMap["RLC"].append(RLCcountSNMap)
        entryTimeTopMap["RLC"].append(RLCentryTimeMap)
        entrySNTopMap["RLC"].append(RLCentrySNMap)
        
    if CUR_DEBUG:
        print "^.^\n" * 5
        print countTimeTopMap["RLC"]
        maxIndex = findBestMappedIndex(countTimeTopMap["RLC"], countTimeTopMap["TCP"], entryTimeTopMap["RLC"], countSNTopMap["RLC"])
        print "Find Max retx index is %d\n Avg transmission is %d" % (maxIndex, util.meanValue(countTimeTopMap["RLC"][maxIndex].values()))
        print countTimeTopMap["RLC"][maxIndex]
    
    return {"ts_count": countTimeTopMap, "ts_byte": byteTimeTopMap, \
            "ts_entry": entryTimeTopMap, "sn_count": countSNTopMap, \
            "sn_entry": entrySNTopMap}

############################################################################
############## Select a group with best for demo purpose ###################
############################################################################
# return the best mapped TCP entry
def findBestMappedIndex(RLCList, TCPList, EntryList, SNCountList):
    maxValue = -1
    maxIndex = -1
    indexOfInterest = []
    # filter out the duplicated sequence number entries    
    for i in range(len(RLCList)):
        if max(RLCList[i].keys()) > max(TCPList[i].keys()):
            indexOfInterest.append(i)
        if util.meanValue([j.rrcID for j in EntryList[i].values()]) > const.DCH_ID:
            indexOfInterest.append(i)
    if not indexOfInterest:
        indexOfInterest = range(len(RLCList))
        print "No entries of interest"
        # return -1

    # the best of the mean * length product
    for i in indexOfInterest:
        #mean = util.meanValue(RLCList[i].values())
        # MAX = max(RLCList[i].values() + [0])
        #length = len(RLCList[i])
        maxCount = max(SNCountList[i].values())
        #maxTCPCount = max(TCPList[i].values())
        #if MAX * length > maxValue:
        #if mean * length > maxValue:
        if maxCount > maxValue:
        #if maxTCPCount > maxValue:
            maxIndex = i
            #maxValue = MAX * length
            #maxValue = mean * length
            maxValue = maxCount
            #maxValue = maxTCPCount
    print "Max Product is %d" % maxValue
    return maxIndex

