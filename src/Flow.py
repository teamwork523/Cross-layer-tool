#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   01/12/2014

TCP flow structure
"""

import sys
import const
import Util as util

class Flow(object):
    """
    Components:
    1. signature: hashed integer of {src_ip, dst_ip, 
                                     transport_layer_protocol_type, 
                                     src_port, dst_port}
                  (regardless of order)
    2. flow: list of TCP packets
    3. properties: 
        (1) http
        (2) index_range: among the whole QxDM trace (min, max)
    """
    def __init__(self, signature):
        self.signature = signature
        self.flow = []
        self.properties = {
            "http": None,\
            "index_range": {"min": None, \
                            "max": None}
            }
        self.cross_layer_trace = []

    # Add new packet to the flow
    def addPacket(self, entry, index):
        self.flow.append(entry)

        # update http type
        if entry.http["type"] != None and \
           entry.http["host"] != None and \
           entry.http["referer"] == None and \
           self.properties["http"] == None:
            self.properties["http"] = entry.http

        # update the range property
        if self.properties["index_range"]["min"] == None or \
           self.properties["index_range"]["min"] > index:
            self.properties["index_range"]["min"] = index            
            
        if self.properties["index_range"]["max"] == None or \
           self.properties["index_range"]["max"] < index:
            self.properties["index_range"]["max"] = index

        # link that entry's flow entry to this instance
        entry.tcp["flow"] = self
    
    # generate the cross layer trace by wrapping around
    # lower layer information for a certain amount of time interval
    def getCrossLayerTrace(self, complete_trace):
        if len(self.cross_layer_trace) > 0:
            return self.cross_layer_trace
        if len(self.flow) == 0:
            print >> sys.stderr, "ERROR: flow length is zero"
        
        flow_start_time = complete_trace[self.properties["index_range"]["min"]].timestamp
        flow_end_time = complete_trace[self.properties["index_range"]["max"]].timestamp

        lower_layer_earliest_time = flow_start_time - const.FLOW_TIME_WIN
        lower_layer_latest_time = flow_end_time + const.FLOW_TIME_WIN

        trace_len = len(complete_trace)

        for start_index in range(self.properties["index_range"]["min"], -1, -1):
            if complete_trace[start_index].timestamp < lower_layer_earliest_time:
                break

        for end_index in range(self.properties["index_range"]["max"], trace_len, 1):
            if complete_trace[end_index].timestamp > lower_layer_latest_time:
                break

        # add lower layer entries in the trace
        flow_set = set(self.flow)

        for i in range(start_index, end_index + 1):
            if complete_trace[i].logID != const.PROTOCOL_ID:
                self.cross_layer_trace.append(complete_trace[i])
            elif i >= self.properties["index_range"]["min"] and \
                 i <= self.properties["index_range"]["max"] and \
                 complete_trace[i] in flow_set:
                self.cross_layer_trace.append(complete_trace[i])

        return self.cross_layer_trace

    # get Hashed value for the flow
    def getHashedPayload(self):
        hashedPayload = []
        for entry in self.flow:
            hashedPayload.append(util.getHashedPayload(entry))
        return hashedPayload

    # get the last the IP packet before the flow
    def getLastPacketBeforeFlow(self, complete_trace):
        indexList = range(self.properties["index_range"]["min"])
        indexList.reverse()
        
        entry = None        
        
        for index in indexList:
            entry = complete_trace[index]
            if entry.logID == const.PROTOCOL_ID:
                return entry

        return entry

    # create signature from a entry
    # if entry is a valid TCP entry, then return signature
    # otherwise, return None
    @staticmethod
    def extractFlowSignature(entry):
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["src_ip"] != None and \
           entry.ip["dst_ip"] != None and \
           entry.ip["tlp_id"] != None and \
           entry.tcp["src_port"] != None and \
           entry.tcp["dst_port"] != None:
            DEL = "+"
            return str(hash(entry.ip["src_ip"]) ^ hash(entry.ip["dst_ip"])) + DEL + \
                   str(entry.ip["tlp_id"]) + DEL + \
                   str(hash(entry.tcp["src_port"]) * hash(entry.tcp["dst_port"]))
        else:
            return None

