#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
The tool parse and analysis the Data Set generated from QXDM filtered log file (in txt)
It could extract IP packets and RLC PDUs, and map them with context information,
i.e. RRC state, RSCP, and etc. One case study for the tool is to study cross-layer
retransmission behavior and investigate the correlation between TCP RTO/Fast retransmission
with RLC retransmission.
"""

import os, sys, time
import const
import QCATEntry as qe
import PCAPPacket as pp
import Util as util
from optparse import OptionParser
import PrintWrapper as pw
import contextWorker as cw
import crossLayerWorker as clw
import retxWorker as rw
import delayWorker as dw
import lossWorker as lw

DEBUG = False
DUP_DEBUG = True
TIME_DEBUG = False

def init_optParser():
    extraspace = len(sys.argv[0].split('/')[-1])+10
    optParser = OptionParser(usage="./%prog [-l, --log] QCAT_LOG_PATH [-m] [-p, --pcap] inPCAPFile\n" + \
                            " "*extraspace + "[-t, --type] protocolType, \n" + \
                            " "*extraspace + "[--src_ip] source_ip, [--dst_ip] destination_ip\n" + \
                            " "*extraspace + "[--dst_ip] dstIP, [--src_port] srcPort\n" + \
                            " "*extraspace + "[--dst_port] destPort, [-b] begin_portion, [-e] end_portion\n" + \
                            " "*extraspace + "[-a] num_packets, [-d] direction, [--srv_ip] server_ip, \n" + \
                            " "*extraspace + "[--print_retx] retransmission_type, [--print_throughput]\n" + \
                            " "*extraspace + "[--retx_analysis], [--retx_count_sig], [--cross_analysis]\n" + \
                            " "*extraspace + "[--verify_cross_analysis], [--keep_non_ip], [--dup_ack_threshold] th\n" + \
                            " "*extraspace + "[--draw_percent] draw, [--loss_analysis], [--udp_hash_target] hash_target")
    optParser.add_option("-a", "--addr", dest="pkts_examined", default=None, \
                         help="Heuristic gauss src/dst ip address. num_packets means the result is based on first how many packets.")
    optParser.add_option("-b", dest="beginPercent", default=0, \
                         help="Beginning point of the sampling")
    optParser.add_option("-d", dest="direction", default=None, \
                         help="Up or down, none specify will ignore throughput")
    optParser.add_option("-e", dest="endPercent", default=1, \
                         help="Ending point of the sampling")
    optParser.add_option("-l", "--log", dest="inQCATLogFile", default="", \
                         help="QCAT log file path")
    optParser.add_option("-m", action="store_true", default=False, dest="isMapping", \
                         help="Add this option when try to map PCAP trace with QCAT log file")
    optParser.add_option("-p", "--pcap", dest="inPCAPFile", default="", \
                         help="PCAP trace file path")
    optParser.add_option("-t", "--type", dest="protocolType", default="TCP", \
                         help="Protocol Type, i.e. TCP or UDP")
    optParser.add_option("--cross_analysis", action="store_true", dest="isCrossAnalysis", default=False, \
                         help="Map the TCP packet with RLC header, then process the cross layer information")
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
    optParser.add_option("--keep_non_ip", action="store_true", dest="keep_non_ip_entries", default=False, \
                         help="Enable it if you want to non-IP entries in the result")
    optParser.add_option("--loss_analysis", action="store_true", dest="is_loss_analysis", default=False, \
                         help="loss ratio analysis over RLC layer")
    optParser.add_option("--print_throughput", action="store_true", dest="is_print_throughput", \
                         help="Flag to enable printing throughput information based on TCP trace analysis")
    optParser.add_option("--print_retx", dest="retxType", default=None, \
                         help="Useful tag to print retx ratio (loss ratio) against each RRC state. Support tcp_rto, tcp_fast, rlc_ul, rlc_dl")
    optParser.add_option("--retx_analysis", action="store_true", dest="enable_tcp_retx_test", default=False, \
                         help="Enable TCP retransmission analysis")
    optParser.add_option("--retx_count_sig", action="store_true", dest="isRetxCountVSSig", default=False, \
                         help="Relate retransmission signal strength with retransmission count")
    optParser.add_option("--src_ip", dest="srcIP", default=None, \
                         help="Filter out entries with source ip")
    optParser.add_option("--src_port", dest="srcPort", default=None, \
                         help="Filter out entries with source port number")
    optParser.add_option("--srv_ip", dest="server_ip", default=None, \
    					  help="Used combined with direction option to filter useful retransmission packets")
    optParser.add_option("--udp_hash_target", dest="hash_target", default="seq", \
    					  help="Hash UDP based on hashed payload, sequence number or more. Current support hash or seq. Useful if you want to use UDP server trace to sync with client side QxDM trace.")
    optParser.add_option("--verify_cross_analysis", action="store_true", dest="verify_cross_analysis", default=False, \
    					  help="Print out each TCP packets and mapped RLC PDU")

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

    # TODO: debug
    if options.ptof_timer:
        const.TIMER["PCH_TO_FACH_ID"] = float(options.ptof_timer)
    if options.ftod_timer:
        const.TIMER["FACH_TO_DCH_ID"] = float(options.ftod_timer)

    # Mapping process
    QCATEntries = util.readQCATLog(options.inQCATLogFile)
    begin = int(float(options.beginPercent)* len(QCATEntries))
    end = int(float(options.endPercent) * len(QCATEntries)) 
    QCATEntries = QCATEntries[begin:end]
    
    # check if just want to print IP
    if options.pkts_examined:
        pw.printIPaddressPair(QCATEntries, options.pkts_examined)
        sys.exit(0)

    if TIME_DEBUG:
        print "Read QxDM takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    #################################################################
    ########################## Pre-process ##########################
    #################################################################
    tempLen = len(QCATEntries)
    print "Before remove dup: %d entries" % (tempLen)
    QCATEntries = util.removeQXDMDupIP(QCATEntries)
    print "After remove dup: %d entries" % (len(QCATEntries))

    if TIME_DEBUG:
        print "Delete Dup IP takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

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
    QCATEntries = cw.extractEntriesOfInterest(QCATEntries, \
                  set((const.PROTOCOL_ID, const.UL_PDU_ID, const.DL_PDU_ID, const.RRC_ID,\
                       const.DL_CONFIG_PDU_ID, const.UL_CONFIG_PDU_ID, const.DL_CTRL_PDU_ID)))

    # create a map between entry and QCATEntry index
    entryIndexMap = util.createEntryMap(QCATEntries)

    # Calculate the RLC RTT based on the polling bit and returned STATUS PDU
    # TODO: right now uplink only
    cw.calc_rlc_rtt(QCATEntries)
    cw.assign_rlc_rtt(QCATEntries)

    if TIME_DEBUG:
        print "Assign Context takes ", time.time() - check_point_time, "sec"
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
    if options.verify_cross_analysis or options.keep_non_ip_entries:
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
    		print >> sys.stderr, "Must specify direction information if you want to filter based on server ip"
    		sys.exit(1)
    	else:
    		cond["ip_relation"] = "or"
    		cond["srv_ip"] = options.server_ip
    filteredQCATEntries = util.packetFilter(QCATEntries, cond)
    # create a map between Filtered entries and its index
    filteredEntryToIndexMap = util.createEntryMap(filteredQCATEntries)

    if TIME_DEBUG:
        print "Filter packets takes ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    #################################################################
    ############### RRC State Inference Verification ################
    #################################################################
    
    #if options.direction:
        #dw.extractFACHStatePktDelayInfo(FACH_delay_analysis_entries, options.direction)
    
    #################################################################
    #################### Retransmission Analysis ####################
    #################################################################
    tcpReTxMap = tcpFastReTxMap = None
    # TCP retransmission process
    if options.enable_tcp_retx_test:
        if options.direction and options.server_ip:
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
        else:
            print >> sys.stderr, "Please specify direction and server ip to apply retransmission analysis"
            sys.exit(1)

    # RLC retransmission process
    [ULReTxCountMap, DLReTxCountMap] = rw.procRLCReTx(QCATEntries)

    # collect statistic information
    retxCountMap, totCountStatsMap, retxRTTMap, totalRTTMap = rw.collectReTxPlusRRCResult(QCATEntries, tcpReTxMap, tcpFastReTxMap)

    if TIME_DEBUG:
        print "Retx analysis takes ", time.time() - check_point_time, "sec"
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
    if TIME_DEBUG:
        print "Start UDP loss Analysis ", time.time() - check_point_time, "sec"
        check_point_time = time.time()

    # Loss ratio is essentially the retransmission ratio
    # use the old retransmission ratio map and the RTT calculation map
    if options.is_loss_analysis:
        # hash table contains only one side traffic
        udp_clt_lookup_table = None
        udp_srv_lookup_table = None

        # calculate the RTT for each UDP packet based on the sequence number
        if options.server_ip and options.direction:
            udp_clt_lookup_table, udp_srv_echo_lookup_table = lw.get_UDP_clt_lookup_table(QCATEntries, \
                                                              options.direction, options.server_ip, options.hash_target)
            if TIME_DEBUG:
                print "UDP: gen clt table ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

            # TODO: only assign RTT if use sequence number for hashing
            if options.hash_target == "seq":
                lw.assign_udp_rtt(QCATEntries, options.direction, udp_clt_lookup_table, udp_srv_echo_lookup_table)

            if TIME_DEBUG:
                print "UDP: Assign RTT takes ", time.time() - check_point_time, "sec"
                check_point_time = time.time()

        if options.inPCAPFile and options.direction:
            options.hash_target = options.hash_target.lower()
            if options.hash_target != "hash" and \
               options.hash_target != "seq":
                optParser.error("--udp_hash_target, only support hash or seq type")
            udp_srv_lookup_table = lw.get_UDP_srv_lookup_table(options.inPCAPFile, options.direction, options.hash_target, options.server_ip)

        if TIME_DEBUG:
            print "UDP: gen srv Table ", time.time() - check_point_time, "sec"
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
                print "UDP: print loss ratio takes ", time.time() - check_point_time, "sec"
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
            print >> sys.stderr, "Must specifiy trace direction!!!"

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
            print >> sys.stderr, "Direction is required to print the TCP and RLC mapping"
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
            print >> sys.stderr, "Direction is required to print retransmission count vs signal s   trength"
    
    
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
    ######################## Verification Section ###################
    #################################################################
    # verify the TCP layer information with RRC layer by printing
    # each TCP packet and corresponding RLC packet
    if options.verify_cross_analysis:
        if options.direction and options.server_ip:
            if options.direction.lower() == "up":
                # pw.print_tcp_and_rlc_mapping_full_version(filteredQCATEntries, filteredEntryToIndexMap, const.UL_PDU_ID, options.server_ip)
                pw.print_tcp_and_rlc_mapping_sn_version(filteredQCATEntries, filteredEntryToIndexMap, const.UL_PDU_ID, options.server_ip)
            else:
                # pw.print_tcp_and_rlc_mapping_full_version(filteredQCATEntries, filteredEntryToIndexMap, const.DL_PDU_ID, options.server_ip)
                pw.print_tcp_and_rlc_mapping_sn_version(filteredQCATEntries, filteredEntryToIndexMap, const.DL_PDU_ID, options.server_ip)
        else:
            print >> sys.stderr, "Must specify the direction and server \
                                  ip to perform the cross layer optimization"

    #################################################################
    ####################### Evaluation Section ######################
    #################################################################


    #################################################################
    ######################## Deprecated Section #####################
    #################################################################
    ################# You can ignore the part below #################
    #################################################################
    # Verify QXDM and PCAP timestamp offset
    # Not useful at this point
    if options.isMapping == True and options.inPCAPFile == "":
        optParser.error("-p, --pcap: Empty PCAP filepath")
    elif options.isMapping == True:
        outFile = "pcapResult.txt"
        # Assume pcapTSVerifier is in the same folder as the current program
        folder = "/".join(sys.argv[0].split("/")[:-1]) + "/"
        print folder
        os.system(folder+"pcapTSVerifier " + options.inPCAPFile + " > " + outFile)

        PCAPPackets = util.readPCAPResultFile(outFile)
        PCAPMaps = util.createTSbasedMap(PCAPPackets)
        QCATMaps = util.createTSbasedMap(QCATEntries)
        countMap = util.mapPCAPwithQCAT(PCAPMaps, QCATMaps)
        totalCount = countMap["fast"] + countMap["slow"] + countMap["same"]
        print "*"*40
        print "In total %d packets"%(len(PCAPPackets))
        print "Mapping rate is %f"%((float)(totalCount)/(float)(len(PCAPPackets)))
        print "QCAT ahead rate is %f"%((float)(countMap["fast"])/(float)(len(PCAPPackets)))
        print "QCAT same rate is %f"%((float)(countMap["same"])/(float)(len(PCAPPackets)))
        print "QCAT slow rate is %f"%((float)(countMap["slow"])/(float)(len(PCAPPackets)))
        print "DCH state rate is %f"%((float)(countMap[const.DCH_ID])/(float)(len(PCAPPackets)))
        print "FACH state rate is %f"%((float)(countMap[const.FACH_ID])/(float)(len(PCAPPackets)))
        print "PCH state rate is %f"%((float)(countMap[const.PCH_ID])/(float)(len(PCAPPackets)))
    #elif options.isMapping == False and options.inPCAPFile != "":
        #optParser.error("Include -m if you want to map PCAP file to QCAT log file")

    # create map between ts and rssi
    """
    if options.sigFile:
        print "Reading from %s ..." % (options.sigFile)
        tsDict = util.readFromSig(options.sigFile)
        print "Finish Reading ..."
        # TODO: sync signal with AGC value
        errDict = util.sycTimeLine(QCATEntries, tsDict)
        print "Mean squared error is %f" % (util.meanValue(errDict.values()))
    """
    # ULRLCOTMap, DLRLCOTMap = cw.mapRLCReTxOverTime(QCATEntries, interval)
    # pw.printRLCReTxMapStats(ULRLCOTMap)
    # pw.printRLCReTxMapStats(DLRLCOTMap)

if __name__ == "__main__":
    main()
