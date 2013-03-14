#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
Logged file for each PCAP entries
"""

import sys

class PCAPPacket:
    def __init__(self, unix_ts_sec, millisec, payload):
        # TODO: may consider to directly overwrite this part with pcap parse library
        self.timestamp = float(unix_ts_sec) + float(millisec)/1000.0
        self.payload = payload.split()
        self.tlp_id = None
        self.__parsePayload()
        
    def __parsePayload(self):
        self.tlp_id = int(self.payload[10], 16)
