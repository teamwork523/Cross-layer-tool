#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   11/10/2013

Validation for RRC inference, feasibility of cross layer mapping and etc.
"""

import os, sys, time
import const
import crossLayerWorker as clw
import PrintWrapper as pw
import Util as util

############################################################################
############################# RRC Inference ################################
############################################################################
# Validate RRC inference algorithm
# Output:
# timestamp \t RRC state
def rrc_inference_validation(entryList):
    for entry in entryList:
        if entry.logID == const.PROTOCOL_ID:
            print str(entry.timestamp) + "\t" + str(entry.rrcID)

# Measure the demotion timer
# Namely the IP packet before the demotion event
def validate_demotion_timer(entryList, carrier=const.TMOBILE, network_type=const.WCDMA):
    DEL = "\t"
    TIMER_UPPER_BOUND = 20
    DEMOTION_LOWER_BOUND = 0.5
    timer_map = {}
    PCH_to_FACH_start = None
    FACH_to_DCH_start = None
    Connect_start = None
    last_priv_IP = None
    last_priv_PDU = None
    if network_type == const.WCDMA:
        if carrier == const.TMOBILE:
            timer_map = {"DCH_to_FACH":[], \
                         "FACH_to_PCH_with_phy_reconfig":[],\
                         "FACH_to_PCH_with_cellUpdate": [],\
                         "FACH_to_DCH":[],\
                         "PCH_to_FACH":[]}
        elif carrier == const.ATT:
            timer_map = {"connect_setup":[], \
                         "DCH_to_Disconnect":[]}
    elif network_type == const.LTE:
        if carrier == const.TMOBILE:
            timer_map = {"Idle_Camped_to_Connected":[], \
                         "Connected_to_Idle_Camped":[]}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.SIG_MSG_ID:
            # 3G
            if network_type == const.WCDMA:
                # T-Mobile 3G
                if carrier == const.TMOBILE:
                    # DCH to FACH
                    if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                       entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.FACH_ID:
                        # privIP = util.find_nearest_ip(entryList, i)
                        privPDU = util.find_nearest_rlc_pdu(entryList, i)
                        if privPDU != None and entry.timestamp - privPDU.timestamp < TIMER_UPPER_BOUND and \
                           entry.timestamp - privPDU.timestamp > DEMOTION_LOWER_BOUND:
                            timer_map["DCH_to_FACH"].append([entry, entry.timestamp - privPDU.timestamp])
                    # FACH to PCH
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_PHY_CH_RECONFIG):
                        #privIP = util.find_nearest_ip(entryList, i)
                        privPDU = util.find_nearest_rlc_pdu(entryList, i)
                        if privPDU != None and entry.timestamp - privPDU.timestamp < TIMER_UPPER_BOUND and \
                           entry.timestamp - privPDU.timestamp > DEMOTION_LOWER_BOUND:
                            timer_map["FACH_to_PCH_with_phy_reconfig"].append([entry, entry.timestamp - privPDU.timestamp])
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP):
                        if PCH_to_FACH_start == None:
                            PCH_to_FACH_start = entry
                        #privIP = util.find_nearest_ip(entryList, i)
                        privPDU = util.find_nearest_rlc_pdu(entryList, i)
                        if privPDU != None and entry.timestamp - privPDU.timestamp < TIMER_UPPER_BOUND and \
                           entry.timestamp - privPDU.timestamp > DEMOTION_LOWER_BOUND:
                            timer_map["FACH_to_PCH_with_cellUpdate"].append([entry, entry.timestamp - privPDU.timestamp])
                    # PCH to FACH
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CELL_UP_CONFIRM):
                        if PCH_to_FACH_start != None  and entry.timestamp - PCH_to_FACH_start.timestamp < TIMER_UPPER_BOUND:
                            timer_map["PCH_to_FACH"].append([entry, entry.timestamp - PCH_to_FACH_start.timestamp])
                            PCH_to_FACH_start = None
                    # FACH to DCH
                    if entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG and \
                       entry.sig_msg["msg"]["rrc_indicator"] and entry.sig_msg["msg"]["rrc_indicator"] == const.DCH_ID:
                        if FACH_to_DCH_start == None:
                            FACH_to_DCH_start = entry
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_RADIO_BEARER_RECONFIG_COMPLETE):
                        if FACH_to_DCH_start != None  and entry.timestamp - FACH_to_DCH_start.timestamp < TIMER_UPPER_BOUND:
                            timer_map["FACH_to_DCH"].append([entry, entry.timestamp - FACH_to_DCH_start.timestamp])
                            FACH_to_DCH_start = None
                # AT&T 3G
                elif carrier == const.ATT:
                    # disconnected to DCH
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_REQUEST):
                        if Connect_start == None:
                            Connect_start = entry
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_SETUP_COMPLETE):
                        if Connect_start != None and entry.timestamp - Connect_start.timestamp < TIMER_UPPER_BOUND:
                            timer_map["connect_setup"].append([entry, entry.timestamp - Connect_start.timestamp])
                            Connect_start = None
                    # DCH to disconnected
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE_COMPLETE):
                        # privIP = util.find_nearest_ip(entryList, i)
                        privPDU = util.find_nearest_rlc_pdu(entryList, i)
                        if last_priv_PDU != None and privPDU != None and privPDU == last_priv_PDU:
                            continue
                        if privPDU != None and entry.timestamp - privPDU.timestamp < TIMER_UPPER_BOUND and \
                           entry.timestamp - privPDU.timestamp > DEMOTION_LOWER_BOUND:
                            last_priv_PDU = privPDU
                            #if entry.timestamp - privIP.timestamp < 20:
                            timer_map["DCH_to_Disconnect"].append([entry, entry.timestamp - privPDU.timestamp])
        # LTE
        elif entry.logID == const.LTE_RRC_OTA_ID:
            if network_type == const.LTE:
                # T-Mobile LTE
                if carrier == const.TMOBILE:
                    # idle camped to connected
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_CCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_REQUEST):
                        if Connect_start == None:
                            Connect_start = entry
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "UL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNCT_RECONFIG_COMPLETE):
                        if Connect_start != None and entry.timestamp - Connect_start.timestamp < TIMER_UPPER_BOUND:
                            timer_map["Idle_Camped_to_Connected"].append([entry, entry.timestamp - Connect_start.timestamp])
                            Connect_start = None
                    # connected to idle camped
                    if (entry.sig_msg["ch_type"] and entry.sig_msg["ch_type"] == "DL_DCCH" and \
                       entry.sig_msg["msg"]["type"] and entry.sig_msg["msg"]["type"] == const.MSG_CONNECT_RELEASE):
                        privIP = util.find_nearest_ip(entryList, i)
                        #privPDU = util.find_nearest_rlc_pdu(entryList, i)
                        if last_priv_IP != None and privIP != None and privIP == last_priv_IP:
                            continue
                        if privIP != None and entry.timestamp - privIP.timestamp < TIMER_UPPER_BOUND and \
                           entry.timestamp - privIP.timestamp > DEMOTION_LOWER_BOUND:
                            last_priv_IP = privIP
                            #if entry.timestamp - privIP.timestamp < 20:
                            timer_map["Connected_to_Idle_Camped"].append([entry, entry.timestamp - privIP.timestamp])
    # print timer result
    for key in timer_map.keys():
        #print key + DEL + str(len(timer_map[key])) + DEL + str(util.quartileResult(timer_map[key]))
        for item in timer_map[key]:
            print key + DEL + str(item[-1]) + DEL + util.convert_ts_in_human(item[0].timestamp)


############################################################################
##################### Cross-layer feasibility ##############################
############################################################################
# Examine the uniqueness of the RLC layer PDU "chain" mapping
# Two possible termination of the chain (WCDMA uplink)
# 1. HE = 2
# 2. The last LI (most likely the second is 127)
def check_mapping_feasibility_uniqueness(entryList, client_ip, direction, network_type="wcdma"):
    # determine the log of interest
    log_of_interest_id = None
    
    # Determine the log of interest we wanna focus on
    log_of_interest_id = util.get_logID_of_interest(network_type, direction)

    non_unique_rlc_tuples, uniqueCount = uniqueness_analysis(entryList, log_of_interest_id)

    print "Non unique RLC tuple length is %d" % (len(non_unique_rlc_tuples))

    # count the key appear twice or more
    dupChainCount = 0.0
    dupPDUCount = 0.0
    totalChainCount = 0.0
    totalPDUCount = 0.0
    DEL = ","
    sortedDuplicateCount = {}   # key is count, value is the chain bytes

    for key, val in uniqueCount.items():
        totalPDUCount += len(key) / 4 * val
        totalChainCount += val
        if val > 1:
            dupPDUCount += len(key) / 4 * val
            dupChainCount += val
            sortedDuplicateCount[val] = key

    # cross-layer analysis to check the untrusted mapping for transport layer
    transport_layer_total_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}    
    valid_transport_layer_mapping_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}
    valid_RLC_first_hop_esimation_count = {const.TCP_ID:0.0, const.UDP_ID:0.0}

    for i in range(len(entryList)):
        entry = entryList[i]
        if entry.logID == const.PROTOCOL_ID:
            # Exclude TCP ACK without payload and TSL without payload
            """
            if entry.ip["tlp_id"] == const.TCP_ID and\
               (entry.ip["total_len"] == 40 or \
                entry.ip["total_len"] == 52 or \
                entry.ip["total_len"] == 83):
                continue
            """
            mapped_RLCs = mapped_sn = None
            if (log_of_interest_id == const.UL_PDU_ID and \
               entry.ip["src_ip"] == client_ip):
                if entry.ip["tlp_id"] in transport_layer_total_count:
                    transport_layer_total_count[entry.ip["tlp_id"]] += 1
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_uplink(entryList, i, log_of_interest_id)
            elif (log_of_interest_id == const.DL_PDU_ID and \
                   entry.ip["dst_ip"] == client_ip):
                if entry.ip["tlp_id"] in transport_layer_total_count:
                    transport_layer_total_count[entry.ip["tlp_id"]] += 1
                mapped_RLCs, mapped_sn = clw.cross_layer_mapping_WCDMA_downlink(entryList, i, log_of_interest_id)
            if mapped_RLCs:
                if is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_of_interest_id, non_unique_rlc_tuples):
                    if entry.ip["tlp_id"] in valid_transport_layer_mapping_count:
                        valid_transport_layer_mapping_count[entry.ip["tlp_id"]] += 1
                if is_valid_first_hop_latency_estimation(mapped_RLCs, mapped_sn, log_of_interest_id):
                    if entry.ip["tlp_id"] in valid_RLC_first_hop_esimation_count:
                        valid_RLC_first_hop_esimation_count[entry.ip["tlp_id"]] += 1                   

    # output results
    print "Chain_occurance" + DEL + "Chain_PDU_length" + DEL + "Chain_value"

    for sortedKey in sorted(sortedDuplicateCount.keys(), reverse=True):
        print str(sortedKey) + DEL + \
              str(len(sortedDuplicateCount[sortedKey]) / 4) + DEL + \
              str(sortedDuplicateCount[sortedKey])
    
    print "$" * 80
    print "Unique Chain ratio %f / %f = %f" % (totalChainCount - dupChainCount, totalChainCount, 1 - dupChainCount / totalChainCount)
    print "Unique PDUs ratio %f / %f = %f" % (totalPDUCount - dupPDUCount, totalPDUCount, 1 - dupPDUCount / totalPDUCount)
    print "Unique TCP ratio %f / %f = %f" % (valid_transport_layer_mapping_count[const.TCP_ID], \
                                             transport_layer_total_count[const.TCP_ID], \
                                             valid_transport_layer_mapping_count[const.TCP_ID] / \
                                             transport_layer_total_count[const.TCP_ID])
    print "Unique UDP ratio %f / %f = %f" % (valid_transport_layer_mapping_count[const.UDP_ID], \
                                             transport_layer_total_count[const.UDP_ID], \
                                             valid_transport_layer_mapping_count[const.UDP_ID] / \
                                             transport_layer_total_count[const.UDP_ID])
    print "Valid TCP first hop esitmation ratio %f / %f = %f" % \
                                            (valid_RLC_first_hop_esimation_count[const.TCP_ID], \
                                             transport_layer_total_count[const.TCP_ID], \
                                             valid_RLC_first_hop_esimation_count[const.TCP_ID] / \
                                             transport_layer_total_count[const.TCP_ID])
    print "Valid UDP first hop esitmation ratio %f / %f = %f" % \
                                            (valid_RLC_first_hop_esimation_count[const.UDP_ID], \
                                             transport_layer_total_count[const.UDP_ID], \
                                             valid_RLC_first_hop_esimation_count[const.UDP_ID] / \
                                             transport_layer_total_count[const.UDP_ID])


# compare total bytes and total number of packet in both uplink and downlink
# Output: statistics about the bytes and packet/PDU counts 
def check_mapping_feasibility_use_bytes(mainEntryList, client_ip):
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

############################################################################
######################## Cross-layer Accuracy ##############################
############################################################################
# Count the number of mapped downlink RLC PDUs
def count_cross_layer_mapping_WCDMA_downlink(entryList, client_ip):
    total_transport_layer_protocol = 0.0
    mapped_transport_layer_protocol = 0.0
    unmapped_entry_list = []

    for entryIndex in range(len(entryList)):
        entry = entryList[entryIndex]
        if entry.logID == const.PROTOCOL_ID and \
           entry.ip["dst_ip"] == client_ip:
            (rlc_list, rlc_sn_list) = clw.cross_layer_mapping_WCDMA_downlink(entryList, entryIndex, const.DL_PDU_ID)
            if rlc_list:
                mapped_transport_layer_protocol += 1
            else:
                unmapped_entry_list.append(entry)
            total_transport_layer_protocol += 1
    
    size_list = [entry.ip["total_len"] for entry in unmapped_entry_list]
    tcp_unmapped_count = 0.0
    total_unmapped_count = float(len(unmapped_entry_list))
    for entry in unmapped_entry_list:
        if entry.ip["tlp_id"] == const.TCP_ID:
            tcp_unmapped_count += 1
    print "Unmapped transport layer size distribution is %s" % (str(util.quartileResult(size_list)))
    print "Unmapped TCP protocol portion is %f / %f = %f" % (tcp_unmapped_count, total_unmapped_count, \
                                                             tcp_unmapped_count / total_unmapped_count)

    print "WCDMA downlink mapping accuracy is %f / %f = %f" % \
          (mapped_transport_layer_protocol, \
           total_transport_layer_protocol, \
           mapped_transport_layer_protocol / total_transport_layer_protocol)

############################################################################
######################## Application Log Accuracy ##########################
############################################################################
# get the application timer from the a file
# Output:
# 1. Map from Host -> Timer -> timestamp
def getApplicationLogTimerMap(inFile):
    f = open(inFile, 'r')
    timerMap = {}
    while True:
        line = f.readline()
        if not line: break
        splittedLine = line.split()
        ts = (float)(splittedLine[0])
        hostname = splittedLine[1]
        timer = (float)(splittedLine[2])
        if hostname not in timerMap:
            timerMap[hostname] = {}
        timerMap[hostname][timer] = ts

    return timerMap

############################################################################
################################# Helper ###################################
############################################################################        
# Valid the uniqueness of the cross-layer mapping
def is_valid_cross_layer_mapping(mapped_RLCs, mapped_sn, log_id, non_unique_rlc_tuples):
    for rlc_pdu in mapped_RLCs:
        entry = rlc_pdu[0]
        pdu = util.find_pdu_based_on_log_id(entry, log_id)
        for sn in pdu["sn"]:
            if (sn in mapped_sn) and \
               ((entry, sn) in non_unique_rlc_tuples):
                return False
    return True

# check whether a polling bit existing for the mapped RLC list
def is_valid_first_hop_latency_estimation(mapped_RLCs, mapped_sn, log_id):
    for rlc_pdu in mapped_RLCs:
        entry = rlc_pdu[0]
        pdu = util.find_pdu_based_on_log_id(entry, log_id)
        for i in range(len(pdu["sn"])):
            sn = pdu["sn"][i]
            if (pdu["header"][i]["p"] != None) and \
               (sn in mapped_sn):
                return True
    return False

# Uniqueness analysis -- filter out the non-unique RLC entries
# Output:
# 1. A set of nonunique RLC tuples with (rlc_entry, sn)
# 2. A map between RLC data chain to the count
def uniqueness_analysis(entryList, log_of_interest_id):
    curKey = ""
    non_unique_rlc_tuples = []
    non_unique_buffer = []
    uniqueCount = {}

    for entry in entryList:
        if entry.logID == log_of_interest_id:
            pdu = util.find_pdu_based_on_log_id(entry, log_of_interest_id)
            for i in range(len(pdu["header"])):
                header = pdu["header"][i]
                sn = pdu["sn"][i]
                if (header.has_key("he") and header["he"] == 2) or (header.has_key("li") and header["li"][-1] == 127):
                    if curKey != "":
                        if curKey in uniqueCount:
                            uniqueCount[curKey] += 1
                            non_unique_rlc_tuples += non_unique_buffer
                            non_unique_buffer = []
                        else:
                            uniqueCount[curKey] = 1
                        # reset the key
                        curKey = ""
                    non_unique_buffer = []
                else:
                    curKey += "".join(header["data"])
                    non_unique_buffer.append((entry, sn))

    return set(non_unique_rlc_tuples), uniqueCount
