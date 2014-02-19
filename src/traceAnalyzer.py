#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
The tool parse and analysis the Data Set generated from QxDM filtered log file (in txt)
It could extract IP packets and RLC PDUs, and map them with context information,
i.e. RRC state, RSCP, and etc. One case study for the tool is to study cross-layer
retransmission behavior and investigate the correlation between TCP RTO/Fast retransmission
with RLC retransmission.
"""

import os, sys, time
import const
import QCATEntry as qe
import PCAPPacket as pp
import PCAPParser as ppsr
import Util as util
from optparse import OptionParser
import PrintWrapper as pw
import contextWorker as cw
import crossLayerWorker as clw
import retxWorker as rw
import delayWorker as dw
import lossWorker as lw
import rootCauseWorker as rcw
import rrcTimerWorker as rtw
import validateWorker as vw
import flowAnalysis as fa
import logcatParser as lp
import QoEAnalysis as qa

DEBUG = False
DUP_DEBUG = False
GAP_DEBUG = False
TIME_DEBUG = True
IP_DUP_DEBUG = False

def init_optParser():
    extraspace = len(sys.argv[0].split('/')[-1])+10
    optParser = OptionParser(usage="./%prog [-f, --file] QCAT_LOG_PATH [-m] [-p, --pcap] inPCAPFile\n" + \
                            " "*extraspace + "[-t, --type] protocolType, \n" + \
                            " "*extraspace + "[--src_ip] source_ip, [--dst_ip] destination_ip\n" + \
                            " "*extraspace + "[--dst_ip] dstIP, [--src_port] srcPort\n" + \
                            " "*extraspace + "[--dst_port] destPort, [-b] begin_portion, [-e] end_portion\n" + \
                            " "*extraspace + "[-a] num_packets, [-d] direction, [--clt_ip] client_ip, [--srv_ip] server_ip, \n" + \
                            " "*extraspace + "[--print_retx] retransmission_type, [ --print_throughput]\n" + \
                            " "*extraspace + "[--retx_analysis], [--retx_count_sig], [--cross_analysis]\n" + \
                            " "*extraspace + "[--cross_mapping_detail], [--keep_non_ip], [--dup_ack_threshold] th\n" + \
                            " "*extraspace + "[--draw_percent] draw, [--loss_analysis], [--udp_hash_target] hash_target\n" + \
                            " "*extraspace + "[--rrc_timer], [--gap_rtt], [--check_cross_mapping_feasibility] type\n" +\
                            " "*extraspace + "[--validate_rrc_state_inference], [--first_hop_latency_analysis]\n" +\
                            " "*extraspace + "[--retx_cross_analysis], [--network_type] network_type\n" +\
                            " "*extraspace + "[--root_cause_analysis] analysis_type, [--validate_downlink], [--large_file]\n" +\
                            " "*extraspace + "[--partition] num_of_partition, [--validate_rrc_timer], [--logcat] logcat_file\n" +\
                            " "*extraspace + "[--check_rrc_transition_occur], [--validate_application_timestamp] app_ts_file\n" +\
                            " "*extraspace + "[-c, --carrier] carrier, [--qoe_file] qoe_file, [--qoe_analysis] qoe_type")
    optParser.add_option("-a", "--addr", dest="pkts_examined", default=None, \
                         help="Heuristic gauss src/dst ip address. num_packets means the result is based on first how many packets.")
    optParser.add_option("-b", dest="beginPercent", default=0, \
                         help="Beginning point of the sampling")
    optParser.add_option("-c", "--carrier", dest="carrier", default=const.TMOBILE, \
                         help="Specify which carrier of interest. Default is T-Mobile")
    optParser.add_option("-d", dest="direction", default=None, \
                         help="Up or down, none specify will ignore throughput")
    optParser.add_option("-e", dest="endPercent", default=1, \
                         help="Ending point of the sampling")
    optParser.add_option("-f", "--file", dest="inQCATLogFile", default="", \
                         help="QCAT log file path")
    optParser.add_option("-m", action="store_true", default=False, dest="isMapping", \
                         help="Add this option when try to map PCAP trace with QCAT log file")
    optParser.add_option("-p", "--pcap", dest="inPCAPFile", default="", \
                         help="PCAP trace file path")
    optParser.add_option("-t", "--type", dest="protocolType", default="TCP", \
                         help="Protocol Type, i.e. TCP or UDP")
    optParser.add_option("--clt_ip", dest="client_ip", default=None, \
    					  help="Client side IP address assuming the device IP address does not change.")
    optParser.add_option("--cross_analysis", action="store_true", dest="isCrossAnalysis", default=False, \
                         help="Map the TCP packet with RLC header, then process the cross layer information")
    optParser.add_option("--check_cross_mapping_feasibility", dest="validate_cross_layer_feasibility", default=None, \
    					 help="Validate the cross-layer mapping feasibility, i.e. byte - compare total bytes in both layers, \
                               unique - check unique PDU chain in the RLC layer")
    optParser.add_option("--check_rrc_transition_occur", action="store_true", dest="isRRCTransitionOccur", default=False, \
    					  help="Check whether RRC state transition occurs")
    optParser.add_option("--cross_mapping_detail", action="store_true", dest="cross_mapping_detail", default=False, \
    					  help="Print out each TCP packets and mapped RLC PDUs")
    #optParser.add_option("--cross_map", action="store_true", dest="isCrossMap", default=False, \
    #                     help="Set this option if you want to map the RLC retransmission with TCP retransmission")
    optParser.add_option("--draw_percent", dest="draw_percent", default=50, \
                         help="The percentage above the line should be count towards benefitial")
    optParser.add_option("--dst_ip", dest="dstIP", default=None, \
                         help="Filter out entries with destination ip")
    optParser.add_option("--dst_port", dest="dstPort", default=None, \
                         help="Filter out entries with destination port number")
    optParser.add_option("--dup_ack_threshold", dest="dup_ack_threshold", default=3, \
                         help="The number of duplicate ack to trigger RLC fast retransmission")
    optParser.add_option("--first_hop_latency_analysis", action="store_true", dest="isFirstHopLatencyAnalysis", default=False, \
                         help="Output the TCP RTT, estimated RLC RTT, and first-hop latency ratio")
    optParser.add_option("--keep_non_ip", action="store_true", dest="keep_non_ip_entries", default=False, \
                         help="Enable it if you want to non-IP entries in the result")
    optParser.add_option("--large_file", action="store_true", dest="is_large_file", default=False, \
                         help="Handle large file that cannot fit into memory all at once")
    optParser.add_option("--logcat", dest="logcat_file", default=None, \
                         help="logcat filepath for QoE analysis")
    optParser.add_option("--loss_analysis", action="store_true", dest="is_loss_analysis", default=False, \
                         help="loss ratio analysis over RLC layer")
    optParser.add_option("--gap_analysis", action="store_true", dest="is_gap_analysis", default=False, \
                         help="study the relationship between the gap period (from RRC inference measurement) to RLC layer retransmission analysis")
    optParser.add_option("--gap_rtt", action="store_true", dest="is_gap_rtt", default=False, \
                         help="Investigate the inter-packet gap time vs the UDP RTT result")
    optParser.add_option("--network_type", dest="network_type", default=const.WCDMA, \
                         help="Specify the cellular network type for the trace, i.e. wcdma, lte")
    optParser.add_option("--partition", dest="num_of_partition", default=None, \
                         help="Generate a data profile file based on the number of partitions")
    optParser.add_option("--print_throughput", action="store_true", dest="is_print_throughput", \
                         help="Flag to enable printing throughput information based on TCP trace analysis")
    optParser.add_option("--print_retx", dest="retxType", default=None, \
                         help="Useful tag to print retx ratio (loss ratio) against each RRC state. Support tcp_rto, tcp_fast, rlc_ul, rlc_dl")
    optParser.add_option("--qoe_file", dest="qoe_file", default=None, \
                         help="User level traces")
    optParser.add_option("--qoe_analysis", dest="qoe_type", default=None, \
                         help="Specify which application for qoe analysis")
    optParser.add_option("--retx_analysis", action="store_true", dest="enable_tcp_retx_test", default=False, \
                         help="Enable TCP retransmission analysis")
    optParser.add_option("--retx_cross_analysis", action="store_true", dest="isRLCRetxAnalysis", default=False, \
                         help="Map transport layer packet with RLC ayer")
    optParser.add_option("--retx_count_sig", action="store_true", dest="isRetxCountVSSig", default=False, \
                         help="Relate retransmission signal strength with retransmission count")
    optParser.add_option("--root_cause_analysis", dest="root_cause_analysis_type", default=None, \
                         help="Perform root cause analysis, i.e. for abnormal inferred RRC state")
    optParser.add_option("--rrc_timer", action="store_true", dest="isValidateRRCTimer", default=False, \
                         help="Include if you want to validate RRC Timer")
    optParser.add_option("--src_ip", dest="srcIP", default=None, \
                         help="Filter out entries with source ip")
    optParser.add_option("--src_port", dest="srcPort", default=None, \
                         help="Filter out entries with source port number")
    optParser.add_option("--srv_ip", dest="server_ip", default=None, \
    					 help="Used combined with direction option to filter useful retransmission packets")
    optParser.add_option("--validate_downlink", action="store_true", dest="validate_downlink", default=False, \
                         help="Validate WCDMA downlink cross-layer mapping")
    optParser.add_option("--validate_rrc_state_inference", action="store_true", dest="isValidateInference", default=False, \
                         help="Validate the RRC inference algorithm by output desired output")
    optParser.add_option("--validate_rrc_timer", action="store_true", dest="isValidateRRCTimer", default=False, \
                         help="Validate the RRC timer values")
    optParser.add_option("--validate_application_timestamp", dest="appTimestampFile", default=None, \
                         help="Validate the time skew of the application File")
    optParser.add_option("--udp_hash_target", dest="hash_target", default="seq", \
    					 help="Hash UDP based on hashed payload, sequence number or more. Current support hash or seq. \
                               Useful if you want to use UDP server trace to sync with client side QxDM trace.")

    # Debugging options
    # optParser.add_option("-s", "--sig", dest="sigFile", default=None, \
    #                     help="Signal strength file")
    optParser.add_option("--ptof_timer", dest="ptof_timer", default=None,\
                         help="Help to Tunning PCH promotion timer")
    optParser.add_option("--ftod_timer", dest="ftod_timer", default=None,\
                         help="Help to Tunning FACH promotion timer")
    return optParser

def main():
    # start to measure time
    start_time = time.time()
    check_point_time = start_time

    # read lines from input file
    optParser = init_optParser()
    (options, args) = optParser.parse_args()

    if options.inQCATLogFile == "":
        optParser.error("-l, --log: Empty QCAT log filepath")
    if options.isMapping == True and options.inPCAPFile == "":
        optParser.error("-p, --pcap: Empty PCAP filepath")
    if options.root_cause_analysis_type == "video_analysis" and \
       options.logcat_file == None:
        optParser.error("--logcat: logcat filepath required")
    if options.qoe_type != None and options.qoe_file == None:
        optParser.error("--qoe_file: must specify user level trace")

    if options.ptof_timer:
        const.TIMER["PCH_TO_FACH_ID"] = float(options.ptof_timer)
    if options.ftod_timer:
        const.TIMER["FACH_TO_DCH_ID"] = float(options.ftod_timer)

    # Output current network type and carrier
    print >> sys.stderr, "Carrier: " + options.carrier + ", network type: " + options.network_type

    if TIME_DEBUG:
        print >> sys.stderr, "Parse options takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    # Check whether need profile to handle large files
    startLine = endLine = None
    if options.is_large_file:
        # check whether need to partition
        if options.num_of_partition != None:
            util.profileQxDMTrace(options.inQCATLogFile, int(options.num_of_partition))
        else:
            # TODO: handle large file based on profile information 
            try:
                with open(const.PROFILE_FILENAME):
                    startLine, endLine = util.loadCurrentPartition()
            except IOError:
                print >> sys.stderr, "ERROR: " + const.PROFILE_FILENAME + " does not exist! \
                                      Please run with --large_file --partition num_of_partition first."
                sys.exit(1)

    # Mapping process
    QCATEntries = util.readQCATLog(options.inQCATLogFile, startLine, endLine)
    begin = int(float(options.beginPercent)* len(QCATEntries))
    end = int(float(options.endPercent) * len(QCATEntries)) 
    QCATEntries = QCATEntries[begin:end]

    # check if just want to print IP
    if options.pkts_examined:
        pw.printIPaddressPair(QCATEntries, options.pkts_examined)
        sys.exit(0)

    if TIME_DEBUG:
        print >> sys.stderr, "Length of Entry List is " + str(len(QCATEntries))
        print >> sys.stderr, "Read QxDM takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    #################################################################
    ########################## Pre-process ##########################
    #################################################################
    if IP_DUP_DEBUG:
        print "\nBefore invalid IP elimination, # of packets is %d\n" % (len(QCATEntries))
    
    # eliminate invalid IP packet due to seperate QxDM logging interface
    QCATEntries = util.eliminateInvalidIPPackets(QCATEntries)

    if IP_DUP_DEBUG:
        print "\nAfter invalid IP elimination, # of packets is %d\n" % (len(QCATEntries))

    # eliminate the IP fragmentation generated by QxDM
    (QCATEntries, ungroupableEntries) = util.groupSegmentedIPPackets(QCATEntries)

    if IP_DUP_DEBUG:
        print "\nAfter group IP packets, # of packets is %d\n" % (len(QCATEntries))

    QCATEntries = util.deDuplicateIPPackets(QCATEntries)

    if IP_DUP_DEBUG:
        print "\nAfter second time deduplicate IP packets, # of packets is %d\n" % (len(QCATEntries))

    if IP_DUP_DEBUG:
        # validate the elimination of IP duplication and fragmenataion
        util.validateIPPackets(QCATEntries)

    # recover the ungroupable entries
    recoveredEntries = util.recoveryUngroupPackets(ungroupableEntries)

    # insert back to the main entry
    QCATEntries = util.insertListOfEntries(QCATEntries, recoveredEntries)

    if IP_DUP_DEBUG:
        print "\nAfter inserting recovered IP packets, # of packets is %d\n" % (len(QCATEntries))

    # Compare with the actual PCAP trace
    if IP_DUP_DEBUG and options.inPCAPFile:
        pcap = ppsr.PCAPParser(options.inPCAPFile, "up", "ip")
        pcap.read_pcap()
        pcap.parse_pcap()
        util.compareQxDMandPCAPtraces(QCATEntries, pcap.ip_trace)

    QCATEntries = util.deDuplicateIPPackets(QCATEntries)

    if IP_DUP_DEBUG:
        print "\nAfter second time deduplicate IP packets, # of packets is %d\n" % (len(QCATEntries))

    if IP_DUP_DEBUG:
        # validate the elimination of IP duplication and fragmenataion
        util.validateIPPackets(QCATEntries)

    if TIME_DEBUG:
        print >> sys.stderr, "Delete Dup IP takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    # determine the client address if user don't pass any IP address hints
    if options.client_ip == None and options.server_ip == None:
        options.client_ip = util.findClientIP(QCATEntries)
    
    if IP_DUP_DEBUG:
        print "Client IP is %s" % (options.client_ip)   

    #################################################################
    ###################### Mapping Context Info #####################
    #################################################################
    #print "Length of Entries is %d" % (len(QCATEntries))
    #TODO: delete the parameters
    #cw.assignRRCState(QCATEntries, float(options.ptof_timer), float(options.ftod_timer))
    cw.assignRRCState(QCATEntries)
    cw.assignEULState(QCATEntries)
    cw.assignSignalStrengthValue(QCATEntries)
    # assign the RLC configuration information
    cw.assignPrivConfiguration(QCATEntries, const.DL_CONFIG_PDU_ID)
    cw.assignPrivConfiguration(QCATEntries, const.UL_CONFIG_PDU_ID)

    """
    # verify configuration assignment
    for index in range(len(QCATEntries)):
        print "*" * 80
        if QCATEntries[index].logID == const.DL_CONFIG_PDU_ID:
            print "!!!!!!!!!!!!!!!!!! New DL config"
        elif QCATEntries[index].logID == const.UL_CONFIG_PDU_ID:
            print "@@@@@@@@@@@@@@@@@@ New UL config"
        print "%d is %s" % (index, QCATEntries[index].dl_config)
        print "%d is %s" % (index, QCATEntries[index].ul_config)
    """
    # assign flow information (deprecated)
    # cw.assignFlowInfo(QCATEntries)
    # use to calculate the buffer range in between two packets
    # TODO: only use for studying FACH state transition delays
    #FACH_delay_analysis_entries = cw.extractEntriesOfInterest(QCATEntries, \
    #              set((const.PROTOCOL_ID, const.UL_PDU_ID, const.DL_PDU_ID, const.RRC_ID)))
    # Optimize by exclude context fields
    # Make sure no change to QCATEntries later on
    """
    QCATEntries = cw.extractEntriesOfInterest(QCATEntries, \
                  set((const.PROTOCOL_ID, const.UL_PDU_ID, const.DL_PDU_ID, const.RRC_ID,\
                       const.DL_CONFIG_PDU_ID, const.UL_CONFIG_PDU_ID, const.DL_CTRL_PDU_ID,\
                       const.SIG_MSG_ID)))
    """

    # create a map between entry and QCATEntry index
    entryIndexMap = util.createEntryMap(QCATEntries)

    # Calculate the RLC RTT based on the polling bit and returned STATUS PDU
    # TODO: right now uplink only
    dw.calc_rlc_rtt(QCATEntries)
    dw.assign_rlc_rtt(QCATEntries)

    if TIME_DEBUG:
        print >> sys.stderr, "Assign Context takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

	#################################################################
    ######################## Protocol Filter ########################
    #################################################################
    # This part is useful for TCP trace analysis, and retransmission analysis
    # contain all the filter based information
    cond = {}
    # this used for filter based on Union or Intersection of all relationships
    cond["ip_relation"] = "and"
    # this used for keep the non-IP entries in the logs
    cond["keep_non_ip_entries"] = False
    # To verify the cross analysis, must include the non ip entries
    if options.root_cause_analysis_type or \
       options.cross_mapping_detail or \
       options.keep_non_ip_entries:
        cond["keep_non_ip_entries"] = True
    if options.srcIP != None:
        if util.validateIP(options.srcIP) == None:
            optParser.error("Invalid source IP")
        else:
            cond["src_ip"] = options.srcIP
    if options.dstIP != None:
        if util.validateIP(options.dstIP) == None:
            optParser.error("Invalid destination IP")
        else:
            cond["dst_ip"] = options.dstIP
    if options.srcPort != None:
        cond["src_port"] = options.src_port
    if options.dstPort != None:
        cond["dst_port"] = options.dst_port
    if options.protocolType != None:
        cond["tlp_id"] = const.TLPtoID_MAP[options.protocolType.upper()]
    if options.server_ip != None:
    	if not options.direction:
    		print >> sys.stderr, "ERROR: Must specify direction information if you want to filter based on server ip"
    		sys.exit(1)
    	else:
    		cond["ip_relation"] = "or"
    		cond["srv_ip"] = options.server_ip

    # if client IP is enabled then use a separate the list entries into two lists
    filteredQCATEntries = []
    filteredEntryToIndexMap = {}
    nonIPEntries = []
    IPEntriesMap = {}

    if options.client_ip != None and \
       (options.cross_mapping_detail):
        (nonIPEntries, IPEntriesMap) = util.multiIPFilter(QCATEntries, options.client_ip)
        
        # double check the quality of filtering
        """
        print "Total trace length is %d" % (len(QCATEntries))
        print "Non IP trace length is %d" % (len(nonIPEntries))
        count = 0
        for key in IPEntriesMap:
            cur_count = len(IPEntriesMap[key])
            count += cur_count
        print "IP trace length is %d" % (count)
        print "The number of distinguished server IPs is %d" % (len(IPEntriesMap.keys()))
        """
    if options.server_ip != None:
        filteredQCATEntries = util.packetFilter(QCATEntries, cond)
        # create a map between Filtered entries and its index
        filteredEntryToIndexMap = util.createEntryMap(filteredQCATEntries)

    if TIME_DEBUG:
        print >> sys.stderr, "Filter packets takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    #################################################################
    #################### Retransmission Analysis ####################
    #################################################################
    tcpReTxMap = tcpFastReTxMap = tcpAllRetxMap = None
    # TCP retransmission process
    if options.enable_tcp_retx_test:
        if options.direction:
            if options.server_ip:
                tcpflows = rw.extractFlows(filteredQCATEntries)

                if DEBUG:
                    print "Filtered QCAT Entry # is %d" % len(filteredQCATEntries)
                    print "TCP flow length is %d" % len(tcpflows)
                tcpReTxMap, tcpFastReTxMap, tcpAllRetxMap = rw.procTCPReTx(tcpflows, options.direction, options.server_ip)
                tcpReTxCount = rw.countTCPReTx(tcpReTxMap)
                tcpFastReTxCount = rw.countTCPReTx(tcpFastReTxMap)

                # combine the Retx Map with the fast retx Map            
                if DEBUG or DUP_DEBUG:
                    print "TCP ReTx happens %d times" % (tcpReTxCount)
                    print "TCP Fast ReTx happens %d times" % (tcpFastReTxCount)

                # Correlate the TCP retransmission information with RLC configuration info
                # CONFIG MAP
                rlc_retx_config_map = clw.getContextInfo(tcpReTxMap, const.DL_CONFIG_PDU_ID)
                rlc_fast_retx_config_map = clw.getContextInfo(tcpFastReTxMap, const.UL_CONFIG_PDU_ID)                
        
    # Peform RLC layer retransmission analysis and collect statistic information
    retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap = rw.collectReTxPlusRRCResult(QCATEntries, tcpReTxMap, tcpFastReTxMap)

    if TIME_DEBUG:
        print >> sys.stderr, "Retx analysis takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time() 

    #################################################################
    #################### TCP Cross Layer Analysis ###################
    #################################################################
    # Apply the one-to-one crosss layer analysis
    # TODO: uplink analysis only right now
    crossMap = {"retx": {}, "fast_retx":{}, "all":{}}
    if options.isCrossAnalysis:
        if options.direction:
            if options.direction.lower() == "up":
                crossMap["retx"] = clw.TCP_RLC_Retx_Mapper(QCATEntries, entryIndexMap, tcpReTxMap, const.UL_PDU_ID)
                crossMap["fast_retx"] = clw.TCP_RLC_Retx_Mapper(QCATEntries, entryIndexMap, tcpFastReTxMap, const.UL_PDU_ID)

                # TODO: delete after checking
                crossMap["all"] = clw.TCP_RLC_Retx_Mapper(QCATEntries, entryIndexMap, tcpAllRetxMap, const.UL_PDU_ID)

                # Only select one sample as best candidate
                #pw.printRetxIntervalWithMaxMap(QCATEntries, entryIndexMap, crossMap["retx"], map_key = "ts_count")
                # TODO: add this back
                # pw.printRetxIntervalWithMaxMap(QCATEntries, entryIndexMap, crossMap["retx"], map_key = "ts_byte")
                # include for debugging
                # TODO: add this back
                #pw.printRetxIntervalWithMaxMap(QCATEntries, entryIndexMap, crossMap["fast_retx"], map_key = "ts_count")
                #pw.printRetxIntervalWithMaxMap(QCATEntries, entryIndexMap, crossMap["fast_retx"], map_key = "ts_byte")
                """
                # print all possible retransmission phenomenon
                pw.printAllRetxIntervalMap(QCATEntries, entryIndexMap, crossMap["retx"], map_key = "ts_byte")
                pw.printAllRetxIntervalMap(QCATEntries, entryIndexMap, crossMap["fast_retx"], map_key = "ts_byte")
                """
                
                rtoShortFACHRatio, err_fach_rto_list = clw.err_demotion_analysis(QCATEntries, entryIndexMap, crossMap["retx"])
                fastRetxShortFACHRatio, err_fach_fast_retx_list = clw.err_demotion_analysis(QCATEntries, entryIndexMap, crossMap["fast_retx"])
                
                rto_config_timer = clw.figure_out_best_timer(QCATEntries, err_fach_rto_list, const.UL_PDU_ID)
                fastRetx_config_timer = clw.figure_out_best_timer(QCATEntries, err_fach_fast_retx_list, const.UL_PDU_ID)
                rto_dup_ack_ratio, rto_dup_ack, rto_total, rto_bit_map = clw.cal_dup_ack_ratio_and_fast_retx_benefit(QCATEntries, entryIndexMap, crossMap["retx"])
                fastRetx_dup_ack_ratio, fastRetx_dup_ack, fastRetx_total, fastRetx_bit_map = clw.cal_dup_ack_ratio_and_fast_retx_benefit(QCATEntries, entryIndexMap, crossMap["fast_retx"])

                all_Retx_dup_ack_ratio, all_Retx_dup_ack, all_Retx_total, all_Retx_bit_map = clw.cal_dup_ack_ratio_and_fast_retx_benefit(QCATEntries, entryIndexMap, crossMap["all"])

                # Assume both arraies have the same length
                retx_bit_map = [rto_bit_map[i] or fastRetx_bit_map[i] for i in range(len(rto_bit_map))]
                
                if DUP_DEBUG:
                    print "Does the bit map matches? %s" % (all_Retx_bit_map == retx_bit_map)
                    print "All Map length is %d, with True number %d" % (len(all_Retx_bit_map), all_Retx_bit_map.count(True))
                    print "RTO OR FAST retx map length is %d, with True number %d" % (len(retx_bit_map), retx_bit_map.count(True))

                # Percentage of dup ack inside the retx range
                # TODO: currently set win_size to be 200 as heuristic
                # status_pdu_map, retx_map, trans_time_benefit_cost_map = clw.rlc_fast_retx_overhead_analysis(QCATEntries, entryIndexMap, 400, retx_bit_map, int(options.dup_ack_threshold), tcpAllRetxMap, int(options.draw_percent))

                # Create the tcp lookup table for true benefit analysis
                tcp_lookup_table = None
                if options.inPCAPFile:
                    tcp_lookup_table = clw.get_TCP_lookup_table(options.inPCAPFile, hash_target = "seq")

                status_pdu_map, retx_map, trans_time_benefit_cost_map, rtt_benefit_cost_time_list, rtt_benefit_cost_count_list, \
                rtt_benefit_cost_time_list_per_state, rtt_benefit_cost_count_list_per_state \
                 = clw.rlc_fast_retx_benefit_overhead_analysis(QCATEntries, entryIndexMap, 400, all_Retx_bit_map, int(options.dup_ack_threshold), tcpAllRetxMap, int(options.draw_percent), tcp_lookup_table)

                # Calculate the total increase or decrease RTT
                total_benefit_cost_time_map, total_benefit_cost_count_map = clw.rlc_fast_retx_overall_benefit(rtt_benefit_cost_time_list, rtt_benefit_cost_count_list)
                # calculate the total benefit/cost per state
                rtt_benefit_cost_per_state_time_map, rtt_benefit_cost_per_state_count_map = clw.rlc_fast_retx_per_rrc_state_benefit(rtt_benefit_cost_time_list_per_state, rtt_benefit_cost_count_list_per_state)
                total_retx_rtt = float(sum(retxRTTMap["rlc_ul"].values()))
                total_retx_count = float(sum(retxCountMap["rlc_ul"].values()))
                total_rtt = float(sum(totalRTTMap["rlc_ul"].values()))
                total_count = float(sum(totCountStatsMap["rlc_ul"].values()))

                if DEBUG:
                    print "RTO: Short FACH ratio is %f" % rtoShortFACHRatio
                    print "RTO: timer distribution %s" % rto_config_timer["time"]
                    print "RTO: Min value of timer is %s" % min(rto_config_timer["time"] + ["N/A"])
                    print "RTO: poll timer distribution is %s" % rto_config_timer["poll_timer"]
                    print "RTO: Average poll timer enabled %f" % util.meanValue(rto_config_timer["poll_timer"])
                    print "Fast Retx: Short FACH promote ratio is %f" % fastRetxShortFACHRatio
                    print "Fast Retx: timer distribution %s" % fastRetx_config_timer["time"]
                    print "Fast Retx: Min value of timer is %s" % min(fastRetx_config_timer["time"] + ["N/A"])
                    print "Fast Retx: Mean value timer is %f" % util.meanValue(fastRetx_config_timer["time"])
                    print "Fast Retx: Average poll timer enabled %f" % util.meanValue(fastRetx_config_timer["poll_timer"])                  
                    # duplicate ACK section
                    print "$"*60
                    print "RTO: Dup_ACK_ratio is %f / %f = %f" % ( rto_dup_ack, rto_total, rto_dup_ack_ratio)
                    print "Fast Retx: Dup_ACK_ratio is %f / %f = %f" % (fastRetx_dup_ack, fastRetx_total, fastRetx_dup_ack_ratio)
                    print "$"*60

                if DUP_DEBUG:
                    pw.print_rlc_fast_retx_cost_benefit(QCATEntries, retx_map, trans_time_benefit_cost_map, rtt_benefit_cost_time_list, rtt_benefit_cost_count_list, total_rtt, total_benefit_cost_time_map, total_count, total_benefit_cost_count_map)
                    # NOTICE: We exclude the retransmission part when we count the total retransmission
                    # print "*" * 30 + " Retx RTT fraction and Retx Count fraction:"
                    # print "RLC retx RTT ratio is %f" % max(total_retx_rtt / (total_rtt - total_retx_rtt), 1)
                    # print "RLC count ratio is %f" % max(total_retx_count / (total_count - total_retx_count), 1)
                    """
                    print "@@@@@@@@@@@ Per State Time Overall List:"
                    print rtt_benefit_cost_time_list_per_state
                    print "@@@@@@@@@@@ Per State Count Overall List:"
                    print rtt_benefit_cost_count_list_per_state
                    print "&&&&&&&&&&& Per State Time Overall Map:"
                    print rtt_benefit_cost_per_state_time_map
                    print "&&&&&&&&&&& Per State Count Map:"
                    print rtt_benefit_cost_per_state_count_map
                    """
                    pw.print_rlc_fast_retx_states_per_RRC_state(status_pdu_map, totalRTTMap, totCountStatsMap, rtt_benefit_cost_per_state_time_map, rtt_benefit_cost_per_state_count_map)
                    
                    

    #################################################################
    ################## UDP Loss + Cross layer Analysis ##############
    #################################################################
    # Loss ratio is essentially the retransmission ratio
    # use the old retransmission ratio map and the RTT calculation map
    # Apply the gap analysis by comparing the transparent work analysis
    if options.is_gap_analysis and options.direction and options.server_ip:
        if TIME_DEBUG:
            print >> sys.stderr, "Start UDP Gap Analysis ", time.time() - check_point_time, "sec"
            check_point_time = time.time()

        #lw.rlc_retx_based_on_gap(filteredQCATEntries, options.direction)
        lw.rlc_retx_based_on_gap(QCATEntries, options.direction)

        if TIME_DEBUG:
            print >> sys.stderr, "Gap RTT Analyais takes ", time.time() - check_point_time, "sec"
            check_point_time = time.time()
    
    # correlate the UDP RTT value with inter-packet time
    if options.is_gap_rtt:
        # calculate the RTT for each UDP packet based on the sequence number
        if options.server_ip and options.direction:
            udp_clt_lookup_table, udp_srv_echo_lookup_table = lw.get_UDP_clt_lookup_table(QCATEntries, \
                                                              options.direction, options.server_ip, options.hash_target)
            if options.hash_target == "seq":
                lw.assign_udp_rtt(QCATEntries, options.direction, udp_clt_lookup_table, udp_srv_echo_lookup_table)
            # print the corresponding RTT for each gap value 
            lw.get_gap_to_rtt_map(QCATEntries)
        #pw.print_loss_ratio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap)
        if TIME_DEBUG:
            print >> sys.stderr, "Gap RTT Analyais takes ", time.time() - check_point_time, "sec"
            check_point_time = time.time()

    if options.is_loss_analysis:
        # hash table contains only one side traffic
        udp_clt_lookup_table = None
        udp_srv_lookup_table = None

        # calculate the RTT for each UDP packet based on the sequence number
        if options.server_ip and options.direction:
            udp_clt_lookup_table, udp_srv_echo_lookup_table = lw.get_UDP_clt_lookup_table(QCATEntries, \
                                                              options.direction, options.server_ip, options.hash_target)
            if TIME_DEBUG:
                print >> sys.stderr, "UDP: gen clt table ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            # TODO: only assign RTT if use sequence number for hashing
            if options.hash_target == "seq":
                lw.assign_udp_rtt(QCATEntries, options.direction, udp_clt_lookup_table, udp_srv_echo_lookup_table)

            if TIME_DEBUG:
                print >> sys.stderr, "UDP: Assign RTT takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()


        if options.inPCAPFile and options.direction:
            options.hash_target = options.hash_target.lower()
            if options.hash_target != "hash" and \
               options.hash_target != "seq":
                optParser.error("--udp_hash_target, only support hash or seq type")
            udp_srv_lookup_table = lw.get_UDP_srv_lookup_table(options.inPCAPFile, options.direction, options.hash_target, options.server_ip)

        if TIME_DEBUG:
            print >> sys.stderr, "UDP: gen srv Table ", time.time() - check_point_time, "sec"
            check_point_time = time.time()
        
        print "Start UDP data: >>>>>>"
        pw.print_loss_ratio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap)

        # map the UDP trace on the client side to the server side
        # NOTICE that we use filtered QCAT Entries
        if udp_clt_lookup_table and udp_srv_lookup_table and options.server_ip:
            loss_state_stats, loss_total_stats, srv_not_recv_list, clt_no_log_list = lw.UDP_loss_stats(QCATEntries, udp_clt_lookup_table, udp_srv_lookup_table, options.hash_target, options.server_ip)
            srv_hash_len = float(len(udp_clt_lookup_table))
            clt_hash_len = float(len(udp_srv_lookup_table))
            clt_no_log_len = float(len(clt_no_log_list))
            print "Client no log ratio is %f / %f = %f" % (clt_no_log_len, clt_hash_len, clt_no_log_len/clt_hash_len)
            # loss ratio per state
            pw.print_loss_ratio_per_state(loss_state_stats, loss_total_stats)

            if TIME_DEBUG:
                print >> sys.stderr, "UDP: print loss ratio takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            # UDP cross analysis
            # TODO: uplink only
            if options.direction.lower() == "up":
                udp_loss_in_cellular, udp_loss_in_internet = lw.UDP_loss_cross_analysis(QCATEntries, srv_not_recv_list, const.UL_PDU_ID)
                pw.print_loss_cause_and_rrc_state(udp_loss_in_cellular, udp_loss_in_internet)

            # UDP RTT analysis
            udp_per_state_rtt_map = lw.cal_UDP_RTT_per_state(QCATEntries, options.direction, udp_clt_lookup_table, udp_srv_echo_lookup_table)
            pw.UDP_RTT_state_information(udp_per_state_rtt_map)

    #################################################################
    ######################## Result Display #########################
    #################################################################
    # A map between Retx count and RSCP based on timestamp
    # TODO: add direction
    #retxRSCPTSbasedMap = cw.buildRetxCountvsRSCP_timebased(QCATEntries, 0.01, const.UL_PDU_ID)
    #pw.printRetxCountvsRSCPbasedOnTS(retxRSCPTSbasedMap)

    # Print throughput for each TCP packets based on sequence number
    if options.is_print_throughput:
        if options.direction:
            cw.calThrouhgput(filteredQCATEntries, options.direction)
        else:
            print >> sys.stderr, "ERROR: Must specifiy trace direction!!!"

    # Print RLC mapping to RRC (timestamp based heuristic)
    # Deprecated
    """
    if options.isCrossMap:
        if options.direction:
            if options.direction.lower() == "up":
                pw.printMapRLCtoTCPRetx(tcpReTxMap, ULReTxCountMap)
            else:
                pw.printMapRLCtoTCPRetx(tcpReTxMap, DLReTxCountMap)
        else:
            print >> sys.stderr, "ERROR: Direction is required to print the TCP and RLC mapping"
    """
    
    # print the retx ratio for each state
    if options.retxType:
        if options.retxType.lower() == "up":
            print "RLC uplink:"
            pw.printRetxRatio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap, "rlc_ul")
            print "TCP RTO uplink:"
            pw.printRetxRatio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap, "tcp_rto")
            print "TCP Fast Retx uplink:"
            pw.printRetxRatio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap, "tcp_fast")
        else:
            pw.printRetxRatio(retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap, options.retxType)
        
    # Correlate the retransmission Count with signal strength
    if options.isRetxCountVSSig:
        if options.direction:
            if options.direction.lower() == "up":
                pw.printRLCRetxCountAndRSCP(ULReTxCountMap) 
            else:
                pw.printRLCRetxCountAndRSCP(DLReTxCountMap)
        else:
            print >> sys.stderr, "ERROR: Direction is required to print retransmission count vs signal strength"
    
    
    # print timeseries plot
    # TODO: add option here
    # pw.printTraceInformation(QCATEntries, const.PROTOCOL_ID)

    # print the signal strength for all specific entries
    """
    if options.direction.lower() == "up":
        pw.printRSCP(QCATEntries, const.UL_PDU_ID)
    else:
        pw.printRSCP(QCATEntries, const.DL_PDU_ID)
    """
    
    #util.procTPReTx_old(QCATEntries)
    #pw.printRetxCountMapList(ULReTxCountMap)
    #print "#"*50
    #pw.printRetxCountMapList(DLReTxCountMap)
    #pw.printRetxSummaryInfo(QCATEntries, ULReTxCountMap, DLReTxCountMap, tcpReTxMap)

    # print result
    #pw.printReTxVSRRCResult(QCATEntries, None)
    
    #################################################################
    ####################### Research Related ########################
    #################################################################
    # Calculate the first hop latency and ratio for RLC layer
    # LIMIT: only support TCP uplink at this moment
    if options.isFirstHopLatencyAnalysis and options.client_ip and options.direction:
        # TCP RTT
        dw.calc_tcp_rtt(QCATEntries)

        tcp_rtt_list = first_hop_rtt_list = ratio_rtt_list = []
        # only support uplink now
        if options.direction.lower() == "up":
            tcp_rtt_list, first_hop_rtt_list, transmission_delay_ratio_rtt_list, \
            ota_delay_ratio_rtt_list = dw.first_hop_latency_evaluation(QCATEntries, const.UL_PDU_ID)
        else:
            tcp_rtt_list, first_hop_rtt_list, transmission_delay_ratio_rtt_list, \
            ota_delay_ratio_rtt_list = dw.first_hop_latency_evaluation(QCATEntries, const.DL_PDU_ID)

        # output the TCP the RTT list
        list_len = len(first_hop_rtt_list)
        DEL = "\t"
        print "TCP_rtt" + DEL + "First_hop_rtt" + DEL + "Tx_delay_ratio" + DEL + "First_hop_rtt_ratio"
        for i in range(list_len):
            print str(tcp_rtt_list[i]) + DEL + \
                  str(first_hop_rtt_list[i]) + DEL + \
                  str(transmission_delay_ratio_rtt_list[i]) + DEL + \
                  str(ota_delay_ratio_rtt_list[i])
        

    # print out retransmission 
    if options.isRLCRetxAnalysis and options.direction and options.client_ip:
        # perform RLC retransmission analysis
        [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(nonIPEntries, detail="simple")
        clMap = {}
        # Get the map between IP entry and the rlc retransmission ratio for that packet
        if options.direction.lower() == "up":
            clMap = rw.crossLayerMappingRLCRetxInfo(QCATEntries, options.direction, \
                    options.client_ip, RLCULReTxCountMap, options.network_type)
        else:
            clMap = rw.crossLayerMappingRLCRetxInfo(QCATEntries, options.direction, \
                    options.client_ip, RLCDLReTxCountMap, options.network_type)
        for v in clMap.values():
            print v

    # Validate the RRC inference timer
    if options.isValidateRRCTimer:
        #vw.validate_rrc_timer(QCATEntries, carrier=options.carrier,\
        #                      network_type=options.network_type)
        vw.print_rrc_process_dalay(QCATEntries, carrier=options.carrier,\
                                   network_type=options.network_type)

    # Check cross-layer mapping feasibility
    if options.validate_cross_layer_feasibility and options.client_ip:
        # Count total number of bytes in the lower layer
        if options.validate_cross_layer_feasibility.lower() == "byte":
            vw.check_mapping_feasibility_use_bytes(QCATEntries, options.client_ip)
        # Check the uniqueness of RLC layer trace (uniqueness analysis)
        if options.validate_cross_layer_feasibility.lower() == "unique":
            if not options.direction:
                print >> sys.stderr, "ERROR: Cross-layer feasibility: Must specify the direction"
                sys.exit(1)
            vw.check_mapping_feasibility_uniqueness(QCATEntries, options.client_ip, options.direction)

    # Check whether RRC state transition occurs in the trace
    if options.isRRCTransitionOccur:
        (dummy, timerMap) = rcw.label_RRC_state_for_IP_packets(QCATEntries)
        print "TimerMap length is " + str(len(timerMap))
        for key in timerMap:
            print const.RRC_MAP[key] + "\t" + str(len(timerMap[key]))

    # ROOT CAUSE analysis
    if options.root_cause_analysis_type:
        if options.root_cause_analysis_type.lower() == "rrc_infer":
            # Analyze the root cause of the abnormal delay
            if options.server_ip == None:
                print >> sys.stderr, "ERROR: Abnormal RRC state root cause analysis parameter error -- no server ip"
                sys.exit(1)
            rcw.abnormal_rrc_fach_analysis(QCATEntries, options.server_ip, options.network_type)
        elif options.root_cause_analysis_type.lower() == "rrc_state_transition":
            print >> sys.stderr, "RRC state transition root cause analysis starts ..."
            # Analyze the root cause for RRC state transition
            if options.direction == None:
                print >> sys.stderr, "ERROR: RRC state transition root cause analysis parameter error -- no direction"
                sys.exit(1)
            rrc_occurance_map, packet_count_map = rcw.rrc_state_transition_analysis(QCATEntries, \
                                                  options.client_ip, options.network_type, options.direction)

            if TIME_DEBUG:
                print >> sys.stderr, "Root cause analysis takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            """
            print "*" * 80
            total_occurance = sum(rrc_occurance_map.values())
            for rrc in sorted(const.RRC_MAP.keys()):
                print str(const.RRC_MAP[rrc]) + (" occurance ratio is %f / %f = %f" % \
                      (rrc_occurance_map[rrc], total_occurance, rrc_occurance_map[rrc] / total_occurance))

            print "\n"
            print "$" * 80
            for key in packet_count_map:
                print "%s ratio is %f / %f = %f" % (key, packet_count_map[key], \
                                                    packet_count_map["total"], \
                                                    packet_count_map[key] / packet_count_map["total"])
            """
        elif options.root_cause_analysis_type.lower() == "rrc_trans_timer":
            # Deprecated: Quantize the RRC transition timer
            # TODO: finish the LTE part
            rcw.rrc_state_transition_timers(QCATEntries)
        elif options.root_cause_analysis_type.lower() == "data_control_interrupt":
            print >> sys.stderr, "Check whether data communication occur within control start ..."
            vw.check_data_trans_during_rrc_trans(QCATEntries, options.carrier, options.network_type)
        elif options.root_cause_analysis_type.lower() == "http_analysis":
            print >> sys.stderr, "HTTP analysis start ..."
            # specific for browsing control experiment
            # extract HTTP information
            fa.parse_http_fields(QCATEntries)

            if TIME_DEBUG:
                print >> sys.stderr, "Parse HTTP fields takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            flows = fa.extractTCPFlows(QCATEntries)
            
            if TIME_DEBUG:
                print >> sys.stderr, "Extract TCP flows takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            
            rcw.performance_analysis_for_browsing(QCATEntries, flows, \
                                                  options.client_ip, \
                                                  options.network_type, \
                                                  carrier=options.carrier)
        elif options.root_cause_analysis_type.lower() == "http_debug":
            print >> sys.stderr, "HTTP analysis debug start ..."
            # specific for browsing control experiment
            # extract HTTP information
            fa.parse_http_fields(QCATEntries)

            if TIME_DEBUG:
                print >> sys.stderr, "Parse HTTP fields takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            flows = fa.extractTCPFlows(QCATEntries)
            
            if TIME_DEBUG:
                print >> sys.stderr, "Extract TCP flows takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()
            #fa.flowRTTDebug(QCATEntries, flows)
            rcw.flow_timeseries_info(QCATEntries, flows, \
                                     options.client_ip, \
                                     options.network_type)
            
        elif options.root_cause_analysis_type.lower() == "validate_flow_analysis":
            fa.validateTCPFlowSigantureHashing(QCATEntries)
        elif options.root_cause_analysis_type.lower() == "detail":
            rcw.trace_detail_rrc_info(QCATEntries, \
                                      options.client_ip, \
                                      options.network_type)
        elif options.root_cause_analysis_type.lower() == "video_analysis":
            print >> sys.stderr, "Start video analysis ..."
            # YouTube case study
            keywords = [const.MEDIA_PLAYER_TAG]
            mediaPlayerTrace = lp.logcatParser(options.logcat_file, keywords)
            stallMap = mediaPlayerTrace.getStallPeriodMap()
            normalIP, stalledIP = util.filterOutStalledIPtraces(QCATEntries, stallMap)
            print "Normal # of IP is " + str(len(normalIP)) + "; Stalled # of IP is " + str(len(stalledIP))
            print "Normal Uplink Throughput: " + str(util.quartileResult(dw.cal_throughput(normalIP, src_ip=options.client_ip)))
            print "Normal Downlink Throughput: " + str(util.quartileResult(dw.cal_throughput(normalIP, dst_ip=options.client_ip)))
            print "Stalled Uplink Throughput: " + str(util.quartileResult(dw.cal_throughput(stalledIP, src_ip=options.client_ip)))
            print "Stalled Downlink Throughput: " + str(util.quartileResult(dw.cal_throughput(stalledIP, dst_ip=options.client_ip)))
            """
            # rcw.video_analysis(QCATEntries, mediaPlayerTrace) 
            fa.parse_http_fields(QCATEntries)

            if TIME_DEBUG:
                print >> sys.stderr, "Parse HTTP fields takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            flows = fa.extractTCPFlows(QCATEntries)
            #print "# of flows is " + str(len(flows))
            if TIME_DEBUG:
                print >> sys.stderr, "Extract TCP flows takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()
            
            rcw.flow_timeseries_info(QCATEntries, flows, \
                                     options.client_ip, \
                                     options.network_type, \
                                     mediaLog = mediaPlayerTrace, \
                                     carrier = options.carrier)             
            """

    # QoE Analysis
    if options.qoe_type:
        if options.qoe_type.lower() == "facebook":
            # Facebook
            qa.facebook_analysis(QCATEntries, options.qoe_file, options.client_ip, \
                                 options.carrier, options.network_type)
        elif options.qoe_type.lower() == "detail":
            # print detail data information for QoE trace
            rcw.trace_detail_rrc_info(QCATEntries, options.client_ip, options.network_type)

    # WCDMA downlink cross-layer mapping validation
    if options.validate_downlink and options.client_ip:
        vw.count_cross_layer_mapping_WCDMA_downlink(QCATEntries, options.client_ip)

    # validate the application timer log timestamp
    if options.appTimestampFile != None:
        DEL = "\t"
        fa.parse_http_fields(QCATEntries)
        flows = fa.extractTCPFlows(QCATEntries)
        timerMap = vw.getApplicationLogTimerMap(options.appTimestampFile)
        for f in flows:
            if f.properties["http"] != None:
                hostname = f.properties["http"]["host"]
                timer = f.properties["http"]["timer"]
                if hostname in timerMap and \
                   timer in timerMap[hostname]:
                    print str(hostname) + DEL + \
                          str(timer) + DEL + \
                          str(abs(f.flow[0].timestamp - timerMap[hostname][timer]))

    ################### For Tmobile ############################
    # verify the TCP layer information with RRC layer by printing
    # each TCP packet and corresponding RLC packet
    if options.cross_mapping_detail and options.enable_tcp_retx_test:
        if options.direction:
            if options.server_ip:
                if options.direction.lower() == "up":
                    # RLC retransmission process
                    # Since the RLC for TCP and UDP are the same, we use a generalized method for retx analysis
                    [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(filteredQCATEntries, detail="simple")
                    pw.print_tcp_and_rlc_mapping_sn_version(filteredQCATEntries, filteredEntryToIndexMap, const.UL_PDU_ID, options.server_ip, tcpAllRetxMap, RLCULReTxCountMap, RLCDLReTxCountMap)
                else:
                    pw.print_tcp_and_rlc_mapping_sn_version(filteredQCATEntries, filteredEntryToIndexMap, const.DL_PDU_ID, options.server_ip, tcpAllRetxMap, RLCULReTxCountMap, RLCDLReTxCountMap)
            elif options.client_ip:
                # perform RLC retransmission analysis
                [RLCULReTxCountMap, RLCDLReTxCountMap] = rw.procRLCReTx(nonIPEntries, detail="simple")
                
                if options.direction.lower() == "up":
                    # WCDMA Uplink
                    # Uniqueness Analysis
                    non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(nonIPEntries, const.UL_PDU_ID)

                    tcp_mapped_ratio_list = []
                    length_list = []
                    retx_list = []
                    rlc_mapped_ratio_list = []
                    
                    if IP_DUP_DEBUG:
                        print "Orig RLC PDU UL #: " + str(util.count_entry_number(nonIPEntries, const.UL_PDU_ID))
                        print "Retx RLC PDU UL #: " + str(util.count_entry_number(RLCULReTxCountMap.keys(), const.UL_PDU_ID))

                    # New: perform multiple server IP mapping
                    DEL = ","
                    # "Note" field indicates whether the cross-layer mapping is unique or not
                    print "Client_IP" + DEL + "Server_IP" + DEL + "Timestamp" + DEL + \
                          "TCP_Sequence_Number" + DEL + "TCP_Retranmission_Count" + DEL + \
                          "TCP_Flag_Info" + DEL + "RLC_Timestamp(first_mapped)" + DEL + \
                          "RLC_Sequence_Number_and_Retransmission_Count" + DEL + \
                          "HTTP_Type" + DEL + "Note"
                    count = 0

                    for ip in IPEntriesMap.keys():
                        # print ">.<" * 40
                        length_list.append(len(IPEntriesMap[ip]))
                        mergedEntries = util.merge_two_entry_lists(nonIPEntries, IPEntriesMap[ip])
                        # print "No. %dth key has merged entry length as %d" % (count, len(mergedEntries))
                        count += 1
                        tcpflows = rw.extractFlows(IPEntriesMap[ip])
                        # print "No. %dth: TCP flow length is %d" % (count, len(tcpflows))
                        tcpReTxMap, tcpFastReTxMap, tcpAllRetxMap = rw.procTCPReTx(tcpflows, options.direction, ip)
                        retx_list.append(len(tcpAllRetxMap))
                        ratios = pw.print_tcp_and_rlc_mapping_sn_version(mergedEntries, util.createEntryMap(mergedEntries), \
                                 const.UL_PDU_ID, ip, tcpAllRetxMap, RLCULReTxCountMap, RLCDLReTxCountMap, non_unique_rlc_tuples, \
                                 withHeader=False, client_ip = options.client_ip)
                        tcp_mapped_ratio_list.append(ratios[0])
                        rlc_mapped_ratio_list.append(ratios[1])

                    if IP_DUP_DEBUG:
                        print "\n" + ":)" * 40
                        print "TCP mapping ratio is %f" % (util.meanValue(tcp_mapped_ratio_list))
                        print "TCP mapping ratio distribution is %s" % (util.quartileResult(tcp_mapped_ratio_list))
                        print "RLC mapped average ratio is %f" % (util.meanValue(rlc_mapped_ratio_list))
                        print "RLC mapped ratio distribution is %s" % (util.quartileResult(rlc_mapped_ratio_list))

                elif options.direction.lower() == "down":
                    # WCDMA Downlink
                    # Uniqueness Analysis
                    non_unique_rlc_tuples, dummy = vw.uniqueness_analysis(nonIPEntries, const.DL_PDU_ID)

                    tcp_mapped_ratio_list = []
                    retx_list = []
                    rlc_mapped_ratio_list = []

                    # New: perform multiple server IP mapping
                    DEL = ","
                    # "Note" field indicates whether the cross-layer mapping is unique or not
                    print "Client_IP" + DEL + "Server_IP" + DEL + "Timestamp" + DEL + \
                          "TCP_Sequence_Number" + DEL + "TCP_Retranmission_Count" + DEL + \
                          "TCP_Flag_Info" + DEL + "RLC_Timestamp(first_mapped)" + DEL + \
                          "RLC_Sequence_Number_and_Retransmission_Count" + DEL + \
                          "HTTP_Type" + DEL + "Note"

                    for ip in IPEntriesMap.keys():
                        mergedEntries = util.merge_two_entry_lists(nonIPEntries, IPEntriesMap[ip])
                        tcpflows = rw.extractFlows(IPEntriesMap[ip])
                        tcpReTxMap, tcpFastReTxMap, tcpAllRetxMap = rw.procTCPReTx(tcpflows, options.direction, ip)
                        retx_list.append(len(tcpAllRetxMap))
                        ratios = pw.print_tcp_and_rlc_mapping_sn_version(mergedEntries, util.createEntryMap(mergedEntries), \
                                 const.DL_PDU_ID, ip, tcpAllRetxMap, RLCULReTxCountMap, RLCDLReTxCountMap, non_unique_rlc_tuples, \
                                 withHeader=False, client_ip = options.client_ip)
                        tcp_mapped_ratio_list.append(ratios[0])
                        rlc_mapped_ratio_list.append(ratios[1])

                    if IP_DUP_DEBUG:                    
                        print "\n" + ":)" * 40
                        print "TCP mapping ratio is %f" % (util.meanValue(tcp_mapped_ratio_list))
                        print "TCP mapping ratio distribution is %s" % (util.quartileResult(tcp_mapped_ratio_list))
                        print "RLC mapped average ratio is %f" % (util.meanValue(rlc_mapped_ratio_list))
                        print "RLC mapped ratio distribution is %s" % (util.quartileResult(rlc_mapped_ratio_list))

if __name__ == "__main__":
    main()
