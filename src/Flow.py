#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   01/12/2014

TCP flow structure
"""

import const

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
    """
    def __init__(self, signature):
        self.signature = signature
        self.flow = []
        self.properties = {
            "http": None}

    # Add new packet to the flow
    def addPacket(self, entry):
        self.flow.append(entry)

        # add http type
        if entry.http["type"] != None and \
           entry.http["host"] != None and \
           entry.http["referer"] == None and \
           self.properties["http"] == None:
            self.properties["http"] = entry.http

        # link that entry's flow entry to this instance
        entry.tcp["flow"] = self

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

