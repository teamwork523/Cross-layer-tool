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

import os, sys
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

DEBUG = True

def init_optParser():
    extraspace = len(sys.argv[0].split('/')[-1])+10
    optParser = OptionParser(usage="./%prog [-l, --log] QCAT_LOG_PATH [-m] [-p, --pcap] inPCAPFile\n" + \
                            " "*extraspace + "[-t, --type] protocolType, \n" + \
                            " "*extraspace + "[--src_ip] source_ip, [--dst_ip] destination_ip\n" + \
                            " "*extraspace + "[--dst_ip] dstIP, [--src_port] srcPort\n" + \
                            " "*extraspace + "[--dst_port] destPort, [-b] begin_portion, [-e] end_portion\n" + \
                            " "*extraspace + "[-a] num_packets, [-d] direction, [--srv_ip] server_ip, [--cross_map]\n" + \
                            " "*extraspace + "[--print_retx] retransmission_type, [--print_throughput]\n" + \
                            " "*extraspace + "[--retx_analysis], [--retx_count_sig]")
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
    optParser.add_option("--print_retx", dest="retxType", default=None, \
                         help="Useful tag to print retx ratio against each RRC state. Support tcp_rto, tcp_fast, rlc_ul, rlc_dl")
    optParser.add_option("--print_throughput", action="store_true", dest="is_print_throughput", \
                         help="Flag to enable printing throughput information based on TCP trace analysis")
    optParser.add_option("--retx_analysis", action="store_true", dest="enable_tcp_retx_test", default=False, \
                         help="Enable TCP retransmission analysis")
    optParser.add_option("--cross_map", action="store_true", dest="isCrossMap", default=False, \
                         help="Set this option if you want to map the RLC retransmission with TCP retransmission")
    optParser.add_option("--retx_count_sig", action="store_true", dest="isRetxCountVSSig", default=False, \
                         help="Relate retransmission signal strength with retransmission count")
    optParser.add_option("--srv_ip", dest="server_ip", default=None, \
    					  help="Used combined with direction option to filter useful retransmission packets")
    optParser.add_option("--src_ip", dest="srcIP", default=None, \
                         help="Filter out entries with source ip")
    optParser.add_option("--dst_ip", dest="dstIP", default=None, \
                         help="Filter out entries with destination ip")
    optParser.add_option("--src_port", dest="srcPort", default=None, \
                         help="Filter out entries with source port number")
    optParser.add_option("--dst_port", dest="dstPort", default=None, \
                         help="Filter out entries with destination port number")
    # Debugging options
    # optParser.add_option("-s", "--sig", dest="sigFile", default=None, \
    #                     help="Signal strength file")
    optParser.add_option("--ptof_timer", dest="ptof_timer", default=None,\
                         help="Help to Tunning PCH promotion timer")
    optParser.add_option("--ftod_timer", dest="ftod_timer", default=None,\
                         help="Help to Tunning FACH promotion timer")
    return optParser

def main():
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
    
    #################################################################
    ########################## Pre-process ##########################
    #################################################################
    tempLen = len(QCATEntries)
    #print "Before remove dup: %d entries" % (tempLen)
    QCATEntries = util.removeQXDMDupIP(QCATEntries)
    #sprint "After remove dup: %d entries" % (len(QCATEntries))

    #################################################################
    ###################### Mapping Context Info #####################
    #################################################################
    #print "Length of Entries is %d" % (len(QCATEntries))
    #TODO: delete the parameters
    #cw.assignRRCState(QCATEntries, float(options.ptof_timer), float(options.ftod_timer))
    cw.assignRRCState(QCATEntries)
    cw.assignEULState(QCATEntries)
    cw.assignSignalStrengthValue(QCATEntries)
    # assign flow information
    # cw.assignFlowInfo(QCATEntries)
    # use to calculate the buffer range in between two packets
    # TODO: only use for studying FACH state transition delays
    FACH_delay_analysis_entries = cw.extractEntriesOfInterest(QCATEntries, \
                  set((const.PROTOCOL_ID, const.UL_PDU_ID, const.DL_PDU_ID, const.RRC_ID)))
    # Optimize by exclude context fields
    # Make sure no change to QCATEntries later on
    QCATEntries = cw.extractEntriesOfInterest(QCATEntries, \
                  set((const.PROTOCOL_ID, const.UL_PDU_ID, const.DL_PDU_ID)))

    #################################################################
    ######################## Cross Layer Maping #####################
    #################################################################
    # create a map between entry and QCATEntry index
    entryIndexMap = util.createEntryMap(QCATEntries)
    
	#################################################################
    ######################## Protocol Filter ########################
    #################################################################
    # This part is useful for TCP trace analysis, and retransmission analysis
    # contain all the filter based information
    cond = {}
    # this used for filter based on Union or Intersection of all relationships
    cond["ip_relation"] = "and"
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
    
    #################################################################
    #################### FACH State delay Process ###################
    #################################################################
    #if options.direction:
        #dw.extractFACHStatePktDelayInfo(FACH_delay_analysis_entries, options.direction)
    
    #################################################################
    #################### Retransmission Process #####################
    #################################################################
    tcpReTxMap = tcpFastReTxMap = None
    # TCP retransmission process
    if options.enable_tcp_retx_test:
        if options.direction and options.server_ip:
            tcpflows = rw.extractFlows(filteredQCATEntries)
            tcpReTxMap, tcpFastReTxMap = rw.procTCPReTx(tcpflows, options.direction, options.server_ip)
            tcpReTxCount = rw.countTCPReTx(tcpReTxMap)
            tcpFastReTxCount = rw.countTCPReTx(tcpFastReTxMap)
            
            # TODO: test on the retransmission layer in uplink 
            pduID = const.UL_PDU_ID
            if options.direction.lower() != "up":
                pduID = const.DL_PDU_ID
            for key in sorted(tcpReTxMap.keys()):
                orig_key = tcpReTxMap[key][0][0]
                retx_key = tcpReTxMap[key][0][1]
                print tcpReTxMap[key][0]
                orig_Mapped_RLCs = clw.mapRLCtoTCP(QCATEntries, entryIndexMap[orig_key], pduID)
                if orig_Mapped_RLCs:
                    retx_Mapped_RLCs = clw.mapRLCtoTCP(QCATEntries, entryIndexMap[retx_key], pduID, hint_index = orig_Mapped_RLCs[-1][1])
                if orig_Mapped_RLCs and retx_Mapped_RLCs:
                    # countMap, byteMap, retxList = clw.RLCRetxMapsForInterval(QCATEntries, orig_Mapped_RLCs[0][1], retx_Mapped_RLCs[-1][1], pduID, retxRLCEntries = orig_Mapped_RLCs + retx_Mapped_RLCs)
                    countMap, byteMap, retxList = clw.RLCRetxMapsForInterval(QCATEntries, orig_Mapped_RLCs[0][1], retx_Mapped_RLCs[-1][1], pduID)
                    print "Retransmission count is %d" % (sum(countMap.values()))
                    print countMap
            """
            item1 = tcpReTxMap[sorted(tcpReTxMap.keys())[1]][0][0]
            item2 = tcpReTxMap[sorted(tcpReTxMap.keys())[1]][0][1]
            rt = clw.mapRLCtoTCP(QCATEntries, entryIndexMap[item1], pduID)
            print "hint_index is %d" % rt[-1][1]
            clw.mapRLCtoTCP(QCATEntries, entryIndexMap[item2], pduID, hint_index = rt[-1][1])
            #clw.mapRLCtoTCP(QCATEntries, entryIndexMap[item2], pduID, hint_index = -1)
            """
            if DEBUG:
                print "TCP ReTx happens %d times" % (tcpReTxCount)
                print "TCP Fast ReTx happens %d times" % (tcpFastReTxCount)
        else:
            print >> sys.stderr, "Please specify direction and server ip to apply retransmission analysis"
            sys.exit(1)
    
    # RLC retransmission process
    [ULReTxCountMap, DLReTxCountMap] = rw.procRLCReTx(QCATEntries)
    
    # collect statistic information
    retxStatsMap, totCountStatsMap = rw.collectReTxPlusRRCResult(QCATEntries, tcpReTxMap, tcpFastReTxMap)

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
    
    # Print RLC mapping to RRC
    if options.isCrossMap:
        if options.direction:
            if options.direction.lower() == "up":
                pw.printMapRLCtoTCPRetx(tcpReTxMap, ULReTxCountMap)
            else:
                pw.printMapRLCtoTCPRetx(tcpReTxMap, DLReTxCountMap)
        else:
            print >> sys.stderr, "Direction is required to print the TCP and RLC mapping"
    
    # print the retx ratio for each state
    if options.retxType:
        pw.printRetxRatio(retxStatsMap, totCountStatsMap, options.retxType)
        
    # Correlate the retransmission Count with signal strength
    if options.isRetxCountVSSig:
        if options.direction:
            if options.direction.lower() == "up":
                pw.printRLCRetxCountAndRSCP(ULReTxCountMap) 
            else:
                pw.printRLCRetxCountAndRSCP(DLReTxCountMap)
        else:
            print >> sys.stderr, "Direction is required to print retransmission count vs signal strength"
    
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
    # You can ignore the part below
    #################################################################
    ################ Verify QXDM and PCAP timing ####################
    #################################################################
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
    elif options.isMapping == False and options.inPCAPFile != "":
        optParser.error("Include -m is you want to map PCAP file to QCAT log file")

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
    # Deprecated:
    # ULRLCOTMap, DLRLCOTMap = cw.mapRLCReTxOverTime(QCATEntries, interval)
    # pw.printRLCReTxMapStats(ULRLCOTMap)
    # pw.printRLCReTxMapStats(DLRLCOTMap)

if __name__ == "__main__":
    main()
