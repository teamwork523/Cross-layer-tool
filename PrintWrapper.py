#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/25/2013
This program print various useful information
"""

import os, sys, re
import const
import QCATEntry as qe
import PCAPPacket as pp
from datetime import datetime

def printResult (entries):
    ULBytes_total = 0.0
    DLBytes_total = 0.0
    ReTxUL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    ReTxDL = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    rrc_state = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    Bytes_on_fly = 0.0
    Trans_retx_bytes = 0.0
    retxul_bytes = {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    retxdl_bytes =  {const.FACH_ID: 0.0, const.DCH_ID: 0.0, const.PCH_ID: 0.0}
    for i in entries:
        ts = i.timestamp[0] + float(i.timestamp[1])/1000.0
        """
        if i.eul["t2p_ec"] != None and i.eul["t2p_ed"] != None:
            print "%f\t%f\t%f" % (ts, i.eul["t2p_ec"], i.eul["t2p_ed"])
        if i.eul["raw_bit_rate"] != None:
            print "%f\t%f" % (ts, i.eul["raw_bit_rate"])
        """
        if i.rrcID != None:
            # print "%f\t%d\t%d\t%d" % (ts, i.rrcID, i.retx["ul"], i.retx["dl"])
            # Timestamp Trans_RT_BYTES UL_RT_BYTES DL_RT_BYTES rrc
            if i.logID == const.PROTOCOL_ID or i.logID == const.UL_PDU_ID or \
               i.logID == const.DL_PDU_ID:
                pass
                #print "%d\t%d\t%d\t%d\t%d" % (ts, i.retx["tp"]*i.ip["total_len"], i.retx["ul"]*i.ul_pdu[0]["size"], \
                 #                         i.retx["dl"]*i.dl_pdu[0]["size"], i.rrcID)
            rrc_state[i.rrcID] += 1
            ReTxUL[i.rrcID] += i.retx["ul"]
            ReTxDL[i.rrcID] += i.retx["dl"]
            if i.logID == const.PROTOCOL_ID:
                Bytes_on_fly += i.ip["total_len"]
                if i.retx["tp"] != 0:
                    Trans_retx_bytes += i.ip["total_len"]                
            if i.logID == const.UL_PDU_ID:
                ULBytes_total += i.ul_pdu[0]["numPDU"]*i.ul_pdu[0]["size"]
                if i.retx["ul"] != 0:
                    retxul_bytes[i.rrcID] += i.retx["ul"]*i.ul_pdu[0]["size"]
            if i.logID == const.DL_PDU_ID:
                DLBytes_total += i.dl_pdu[0]["size"]
                if i.retx["dl"] != 0:
                    retxdl_bytes[i.rrcID] += i.retx["dl"]*i.dl_pdu[0]["size"]
            
    # print "***************"
    totUL = float(ReTxUL[2]+ReTxUL[3]+ReTxUL[4])
    totDL = float(ReTxDL[2]+ReTxDL[3]+ReTxDL[4])
    totState = float(rrc_state[2]+rrc_state[3]+rrc_state[4])
    totULBytes = float(retxul_bytes[2]+retxul_bytes[3]+retxul_bytes[4])
    totDLBytes = float(retxdl_bytes[2]+retxdl_bytes[3]+retxdl_bytes[4])
    # print "%d\t%d\t%d\t%d\t%d\t%d" % (ReTxUL[const.FACH_ID], ReTxUL[const.DCH_ID], ReTxUL[const.PCH_ID], ReTxDL[const.FACH_ID], ReTxDL[const.DCH_ID], ReTxDL[const.PCH_ID])
    
    """
    print "Total UL retx: %f" % (totUL)
    print "Total DL retx: %f" % (totDL)
    print "Total RRC state: %f" % (totState)
    """
    print "Total bytes on fly: %f" % (Bytes_on_fly)
    print "Total retx bytes on IP: %f" % (Trans_retx_bytes)
    print "Total Uplink bytes: %d" % (ULBytes_total)
    print "Total Downlink bytes: %d" % (DLBytes_total)
    print "Total Uplink RT bytes: %f" % (totULBytes)
    print "Total Downlink RT bytes: %f" % (totDLBytes)
    """
    if totUL != 0.0:
        print "UL -- FACH %f, DCH %f, PCH %f" % (ReTxUL[const.FACH_ID]/totUL, ReTxUL[const.DCH_ID]/totUL, ReTxUL[const.PCH_ID]/totUL)
    if totDL != 0.0:
        print "DL -- FACH %f, DCH %f, PCH %f" % (ReTxDL[const.FACH_ID]/totDL, ReTxDL[const.DCH_ID]/totDL, ReTxDL[const.PCH_ID]/totDL)
    if totState != 0.0:
        print "State dist -- FACH %f, DCH %f, PCH %f" % (rrc_state[const.FACH_ID]/totState, rrc_state[const.DCH_ID]/totState, rrc_state[const.PCH_ID]/totState)
    if Bytes_on_fly != 0:
        print "RT fraction : %f" % ((totULBytes+totDLBytes)/Bytes_on_fly)
    if totULBytes != 0.0:
        print "UL Retx bytes -- FACH %f, DCH %f, PCH %f" % (retxul_bytes[const.FACH_ID]/totULBytes, retxul_bytes[const.DCH_ID]/totULBytes, retxul_bytes[const.PCH_ID]/totULBytes)
    if totDLBytes != 0.0:
        print "DL Retx bytes -- FACH %f, DCH %f, PCH %f" % (retxdl_bytes[const.FACH_ID]/totDLBytes, retxdl_bytes[const.DCH_ID]/totDLBytes, retxdl_bytes[const.PCH_ID]/totDLBytes)
    """
