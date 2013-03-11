#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/02/2013
This program analyze the Data Set generated from QXDM filtered log file
It could optionally map the packets from PCAP with the RRC states in the log
"""

import os, sys
import const
import QCATEntry as qe
import PCAPPacket as pp
import Util as util
from optparse import OptionParser
import PrintWrapper as pw

def init_optParser():
    extraspace = len(sys.argv[0].split('/')[-1])+10
    optParser = OptionParser(usage="./%prog [-l, --log] QCAT_LOG_PATH [-m] [-p, --pcap] inPCAPFile\n" + \
                            " "*extraspace + "[-t, --type] protocolType, [--src_ip] srcIP\n" + \
                            " "*extraspace + "[--src_ip] source_ip, [--dst_ip] destination_ip\n" + \
                            " "*extraspace + "[--dst_ip] dstIP, [--src_port] srcPort\n" + \
                            " "*extraspace + "[--dst_port] destPort, [-b] begin_portion, [-e] end_portion\n" + \
                            " "*extraspace + "[-a] Threshold, [-d] direction, [--srv_ip] server_ip")
    optParser.add_option("-a", "--addr", dest="printAddr", default=None, \
                         help="Print IP address")
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
    # TODO: delete after debugging
    # optParser.add_option("-s", "--sig", dest="sigFile", default=None, \
    #                     help="Signal strength file")
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
                         
    return optParser

def main():
    # read lines from input file
    optParser = init_optParser()
    (options, args) = optParser.parse_args()

    if options.inQCATLogFile == "":
        optParser.error("-l, --log: Empty QCAT log filepath")
    if options.isMapping == True and options.inPCAPFile == "":
        optParser.error("-p, --pcap: Empty PCAP filepath")
 
    # Mapping process
    QCATEntries = util.readQCATLog(options.inQCATLogFile)
    begin = int(float(options.beginPercent)* len(QCATEntries))
    end = int(float(options.endPercent) * len(QCATEntries)) 
    QCATEntries = QCATEntries[begin:end]
    
    # check if just want to print IP
    if options.printAddr:
        pw.printIPaddressPair(QCATEntries, options.printAddr)
        sys.exit(0)
       
    #################################################################
    ###################### Mapping Context Info #####################
    #################################################################
    #print "Length of Entries is %d" % (len(QCATEntries))
    util.assignRRCState(QCATEntries)
    util.assignEULState(QCATEntries)
    tempLen = len(QCATEntries)
    #print "Before remove dup: %d entries" % (tempLen)
    QCATEntries = util.removeQXDMDupIP(QCATEntries)
    #print "After remove dup: %d entries" % (len(QCATEntries))
    util.assignSignalStrengthValue(QCATEntries)
    # assign flow information
    # util.assignFlowInfo(QCATEntries)
	
	#################################################################
    ######################## Protocol Filter ########################
    #################################################################
    # validate ip address
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
    #################### Retransmission Process #####################
    #################################################################
    # TCP retransmission process
    # TODO: current retransmission is required to filter one direction of traffic
    # 		Improve this by flow analysis  
    if options.direction and options.server_ip:
		tcpflows = util.extractFlows(filteredQCATEntries)
		tcpReTxMap, tcpFastReTxMap = util.procTCPReTx(tcpflows, options.direction, options.server_ip)
		tcpReTxCount = util.countTCPReTx(tcpReTxMap)
		tcpFastReTxCount = util.countTCPReTx(tcpFastReTxMap)
		#print "TCP ReTx happens %d times" % (tcpReTxCount)
		#print "TCP Fast ReTx happens %d times" % (tcpFastReTxCount)
    else:
		print >> sys.stderr, "Must specify direction and server ip to analysis retransmission"
    """
    if options.srcIP or options.dstIP:
    	tcpReTxMap = util.procTCPReTx(tcpflows)
        tcpReTxCount = util.countTCPReTx(tcpReTxMap)
        print "TCP ReTx is %d" % (tcpReTxCount)
    else:
		print >> sys.stderr, "Must use filter to apply retransmission count"
	"""
    # print "Total Duplicate Transmission is %d" % (filteredReTxCount)
    
    
    """
    if options.srcIP != None:
        print "Sender retx count is %d" % (filteredReTxCount)
    if options.dstIP != None:
        print "Receiver retx count is %d" % (filteredReTxCount)
    for i in QCATEntries:
        if i.rrcID != None and i.ip["tlp_id"] != None:
            print "RRC: %d, Protocol: %d" % (i.rrcID, i.ip["tlp_id"])
    """

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
    
    #################################################################
    ######################## Result Display #########################
    #################################################################
    # Compute throughput
    if options.direction:
        util.calThrouhgput(filteredQCATEntries, options.direction)
    else:
        print >> sys.stderr, "Ignore throughput calculation!!!"
    
    [ULReTxCountMap, DLReTxCountMap] = util.procRLCReTx(QCATEntries)
    #pw.printRetxCountMapList(ULReTxCountMap)
    #print "#"*50
    #pw.printRetxCountMapList(DLReTxCountMap)
    # pw.printRetxSummaryInfo(QCATEntries, ULReTxCountMap, DLReTxCountMap, tcpReTxMap)
    if options.direction:
    	if options.direction.lower() == "up":
	     	pw.printTwoRetx(tcpReTxMap, ULReTxCountMap)
        else:
	    	pw.printTwoRetx(tcpReTxMap, DLReTxCountMap)
    else:
        print >> sys.stderr, "ooops, no compare between TCP and RLC retx"
    
    # pw.printRSCP(QCATEntries)
    # print result
    #pw.printULCount(QCATEntries)
    #pw.printDLCount(QCATEntries)
    # pw.printReTxVSRRCResult(QCATEntries)
    #pw.printThroughput(QCATEntries)
    #pw.printRSSIvsTransReTx(QCATEntries)
    #pw.printRSSIvsLinkReTx(QCATEntries)
    
    
    #################################################################
    ################ Verify QXDM and PCAP timing ####################
    #################################################################
    # Not useful at this point
    if options.isMapping == True and options.inPCAPFile == "":
        optParser.error("-p, --pcap: Empty PCAP filepath")
    elif options.isMapping == True:
        outFile = "pcapResult.txt"
        os.system("pcap/main " + options.inPCAPFile + " > " + outFile)

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

if __name__ == "__main__":
    main()
