#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   01/12/2014

TCP flow class analysis including HTTP related parsing as well
"""

import sys
import const
import crossLayerWorker as clw
import delayWorker as dw
import PrintWrapper as pw
import retxWorker as rw
import Util as util
import validateWorker as vw
from Flow import Flow

FLOW_CHECK = False
TIMER_CHECK = False
HTTP_EXTRA = False

############################################################################
################################ TCP Flows #################################
############################################################################
# extract TCP flows
# Return a list of TCP flows
def extractTCPFlows(entryList):
    finishedFlows = []
    # a map between flow's signature and flow
    ongoingFlows = {}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.TCP_ID:
            flow_signature = Flow.extractFlowSignature(entry)
            if flow_signature:
                if entry.tcp["SYN_FLAG"] and not entry.tcp["ACK_FLAG"]:
                    # capture a new flow by SYN packet
                    if not ongoingFlows.has_key(flow_signature):
                        # create a new flow
                        ongoingFlows[flow_signature] = Flow(flow_signature)
                        ongoingFlows[flow_signature].addPacket(entry, i)
                elif entry.tcp["FIN_FLAG"]:
                    # finish a TCP flow if there is one
                    if ongoingFlows.has_key(flow_signature):
                        ongoingFlows[flow_signature].addPacket(entry, i)
                        finishedFlows.append(ongoingFlows[flow_signature])
                        del ongoingFlows[flow_signature]
                else:
                    # add to existing ongoing flow
                    if ongoingFlows.has_key(flow_signature):
                        ongoingFlows[flow_signature].addPacket(entry, i)

    # wrap up anything leftover flow
    for flow in ongoingFlows.values():
        finishedFlows.append(flow)

    if FLOW_CHECK:
        for f in finishedFlows:
            if f.properties["http"] != None:
                line = str(f.properties["http"]) + "\t" + str(len(f.flow)) + "\t" + \
                       util.convert_ts_in_human(f.flow[0].timestamp)
                if f.flow[0].rrcID != None:
                    line += "\t" + const.RRC_MAP[f.flow[0].rrcID]
                print line
                # print pw.printTCPEntry(f.flow[0])
        print "*" * 60
        print "Total # of flows are " + str(len(finishedFlows))
  
    return finishedFlows 

# Validate TCP flow signature hash
def validateTCPFlowSigantureHashing(entryList):
    hashToFiveTupleMap = {}
    DEL = "+"

    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["tlp_id"] == const.TCP_ID:
            five_tuple = str(entry.ip["src_ip"]) + DEL + \
                         str(entry.ip["dst_ip"]) + DEL + \
                         str(entry.ip["tlp_id"]) + DEL + \
                         str(entry.tcp["src_port"]) + DEL + \
                         str(entry.tcp["dst_port"])
            hashed_tuple = Flow.extractFlowSignature(entry)
            if hashToFiveTupleMap.has_key(hashed_tuple):
                if five_tuple not in hashToFiveTupleMap[hashed_tuple]:
                    hashToFiveTupleMap[hashed_tuple].append(five_tuple)
            else:
                hashToFiveTupleMap[hashed_tuple] = [five_tuple]

    valid = True
    for key,value in hashToFiveTupleMap.items():
        if len(value) != 2:
            valid = False
            print "Hashed Key: " + key + "\n" + "Tuples: " + value

    if valid:
        print "SUCCESS: hashing is valid !!!"
    else:
        print "ERROR: hashing is invalid !!!"

############################################################################
############################## HTTP Specific ###############################
############################################################################
# Pair up the flow based on HTTP hostname
# input:
# 1. HTTP flows
#
# Output tuple of flows
# 1. Nearest tuple of HTTP flows
def pair_up_flows(flows):
    pairs = []
    flow_len = len(flows)
    visited_indices = set()

    for i in range(flow_len):
        visited_indices.add(i)
        if flows[i].properties["http"] == None:
            continue
        for j in range(i+1, flow_len):
            # must occur within a time period
            if abs(flows[i].flow[0].timestamp - flows[j].flow[0].timestamp) > const.MAX_PAIR_TIME_DIFF:
                break
            if flows[j].properties["http"] == None:
                continue
            if j not in visited_indices and \
               flows[i].properties["http"]["host"] == flows[j].properties["http"]["host"]:
                visited_indices.add(j)
                pairs.append((flows[i], flows[j]))
                break
    
    return pairs


# extract HTTP fields (Assume all the IP packets are pre-processed)
# As HTTP fields don't have a strict order, we have to check them one by one
# 1. Host
# 2. Referer
def parse_http_fields(entryList):
    count = 0
    goodCount = 0
    DEL = "\t"

    if HTTP_EXTRA:
        # Assign TCP RTT
        dw.calc_tcp_rtt(entryList)
        log_of_interest_id = get_logID_of_interest("wcdma", "up")

        # Uniqueness analysis
        non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(entryList, log_of_interest_id)

        # RLC retransmission analysis
        [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(entryList, detail="simple")

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID and \
           entry.tcp["dst_port"] == const.HTTP_DST_PORT:
            http_payload = entry.hex_dump["payload"][(const.Payload_Header_Len + \
                                                     entry.ip["header_len"] + \
                                                     entry.tcp["header_len"]):]
            http_payload_by_field = "".join(http_payload).decode("hex").split(const.HTTP_LINE_DEL)
            for field in http_payload_by_field:
                splitted_field = field.split(const.HTTP_FIELD_DEL)
                if splitted_field[0].lower() == "host":
                    entry.http["host"] = splitted_field[1]
                elif splitted_field[0].lower() == "referer":
                    entry.http["referer"] = splitted_field[1]
                elif splitted_field[0].lower() == "timer":
                    entry.http["timer"] = float(splitted_field[1])

                    # move on to the next entry when we get what we want
                    if TIMER_CHECK:
                        if entry.http["host"] and \
                           entry.http["timer"] and \
                           entry.http["host"] in const.HOST_OF_INTEREST:
                            print entry.http
            line = ""
            if HTTP_EXTRA:
                if entry.http["host"] or entry.http["referer"]:
                    count += 1
                    line += util.convert_ts_in_human(entry.timestamp) + DEL + \
                            str(const.RRC_MAP[entry.rrcID]) + DEL + \
                            str(entry.http) + DEL
                
                    # check whether interference exist
                    mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
                    if mapped_RLCs:
                        if vw.is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                            if entry.rtt["tcp"]:
                                paraCountMap = count_prach_aich_status(entryList, mapped_RLCs[0][-1], mapped_RLCs[-1][-1], const.PRACH_PARA_ID)
                                line += str(paraCountMap[const.PRACH_ABORT]) + DEL
                                line += str(paraCountMap[const.PRACH_DONE]) + DEL
                                eventCountMap = count_prach_aich_status(entryList, mapped_RLCs[0][-1], mapped_RLCs[-1][-1], const.EVENT_ID)
                                line += str(eventCountMap[const.PRACH_ABORT]) + DEL
                                line += str(eventCountMap[const.PRACH_DONE]) + DEL
                                if paraCountMap[const.PRACH_ABORT] > 0 or \
                                   paraCountMap[const.PRACH_DONE] > 0 or \
                                   eventCountMap[const.PRACH_ABORT] > 0 or \
                                   eventCountMap[const.PRACH_DONE] > 0:
                                    goodCount += 1    
                                    line += "Interred_request"
                            else:
                                line += "ERROR: fail to estimate TCP rtt"
                        else:
                            line += "ERROR: not unique mapping"
                    else:
                        line += "ERROR: not mapped RLC PDUs"
                    print line
    if HTTP_EXTRA:
        print "*"*80
        print "In total, " + str(count) + " requests."
        print "Interfered URL is " + str(goodCount)


############################################################################
################################# Debug ####################################
############################################################################
# Investigate why no RTTs
#
# Print the Relative ACK and SYN number
# 
def flowRTTDebug(entryList, flows):
    # estimate the rtt first
    # dw.calc_tcp_rtt(entryList)
    effective_request_count = {"uplink": [], "downlink": []}
    effective_request_ratio = {"uplink": [], "downlink": []}

    DEL = "\t"
    for f in flows:
        if f.properties["http"] != None and f.flow != None:
            uplinkEffectiveCount = 0.0
            downlinkEffectiveCount = 0.0

            print "*" * 80
            print str(f.properties["http"])
            print "*" * 80

            #dw.calc_tcp_rtt(f.flow)
            flowTrace = f.getCrossLayerTrace(entryList)
            dw.calc_tcp_rtt(flowTrace)

            (synPacket, synackPacket) = findSYNandSYNACKpacket(flowTrace)
            if not synPacket:
                print "ERROR: no SYN packet found!"
                break
            if not synackPacket:
                print "ERROR: no SYN/ACK packet found!"
                break
            baseTime = synPacket.timestamp
            clt_ip = synPacket.ip["src_ip"]
            cltSeqBase = synPacket.tcp["seq_num"]
            srvSeqBase = synackPacket.tcp["seq_num"]
        
            # header
            print "Time" + DEL +\
                  "Clt/Srv" + DEL +\
                  "Seq Number" + DEL +\
                  "Ack Number" + DEL +\
                  "Payload Size" + DEL +\
                  "RTT"

            # print out the actual flow
            for tcpPacket in f.flow:
                line = ""
                payload = tcpPacket.ip["total_len"] - tcpPacket.ip["header_len"] - \
                          tcpPacket.tcp["header_len"]
                # client request
                if tcpPacket.ip["src_ip"] == clt_ip:
                    if payload > 0:
                        uplinkEffectiveCount += 1 
                    line += str(tcpPacket.timestamp - baseTime) + DEL + \
                            "Client" + DEL + \
                            str(tcpPacket.tcp["seq_num"] - cltSeqBase) + DEL + \
                            str(tcpPacket.tcp["ack_num"] - srvSeqBase) + DEL + \
                            str(payload) + DEL
                    if tcpPacket.rtt["tcp"] != None:
                        line += str(tcpPacket.rtt["tcp"] * 1000.0)
                    else:
                        line += "None"
                else:
                    if payload > 0:
                        downlinkEffectiveCount += 1
                    line += str(tcpPacket.timestamp - baseTime) + DEL + \
                            "Server" + DEL + \
                            str(tcpPacket.tcp["seq_num"] - srvSeqBase) + DEL + \
                            str(tcpPacket.tcp["ack_num"] - cltSeqBase) + DEL + \
                            str(payload) + DEL
                    if tcpPacket.rtt["tcp"]:
                        line += str(tcpPacket.rtt["tcp"] * 1000)
                    else:
                        line += "None"

                print line

            effective_request_count["uplink"].append(uplinkEffectiveCount)
            effective_request_count["downlink"].append(downlinkEffectiveCount)
            totalCount = uplinkEffectiveCount + downlinkEffectiveCount
            try:
                effective_request_ratio["uplink"].append(float(uplinkEffectiveCount / totalCount))
                effective_request_ratio["downlink"].append(float(downlinkEffectiveCount / totalCount))
            except ZeroDivisionError:
                print "ERROR: invalid flow!!!"

    print "#" * 80
    print "Uplink Effective Data request: " + str(util.quartileResult(effective_request_count["uplink"]))
    print "Uplink Effective Data ratio: " + str(util.quartileResult(effective_request_ratio["uplink"]))
    print "Downlink Effective Data request: " + str(util.quartileResult(effective_request_count["downlink"]))
    print "Downlink Effective Data ratio: " + str(util.quartileResult(effective_request_ratio["downlink"]))

############################################################################
################################# Helper ####################################
############################################################################

# find the SYN and SYN/ACK packet in the flow
# return SYN and SYN/ACK packets in pairs
def findSYNandSYNACKpacket(flowPackets):
    synPacket = synackPacket = None

    for packet in flowPackets:
        if packet.tcp["SYN_FLAG"] and not packet.tcp["ACK_FLAG"]:
            synPacket = packet
        if packet.tcp["SYN_FLAG"] and packet.tcp["ACK_FLAG"]:
            synackPacket = packet
        if synPacket and synackPacket:
            break

    return (synPacket, synackPacket)

# find the first HTTP GET request
# Output
# 1. request entry
# 2. index of the entry in the trace
def findTheInitHTTPReqeuest(flow, trace):
    clt_ip = flow[0].ip["src_ip"]
    request = None
    for packet in flow:
        if packet.ip["src_ip"] == clt_ip:
            payload = packet.ip["total_len"] - packet.ip["header_len"] - \
                      packet.tcp["header_len"]
            if payload > 0:
                request = packet
                break
    i = 0
    if request != None:
        try:
            i = trace.index(request)
        except ValueError:
            i = None

    return (request, i)

# find the last data payload
# WARNING: heurstic approach, find the last TCP packet that payload is not zero bytes
def findLastPayload(flow):
    indices = range(len(flow))
    indices.reverse()
    for i in indices:
        packet = flow[i]
        payloadSize = packet.ip["total_len"] - packet.ip["header_len"] - \
                      packet.tcp["header_len"]
        if payloadSize > 0:
            return packet
    return None

