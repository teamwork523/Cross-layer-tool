The project is a tool that parse QCAT logs and apply post data analysis.

Author
--------------
- Haokun Luo (haokun@umich.edu)


Installation Dependency
--------------
- World Timezone Defitions (http://pytz.sourceforge.net/)
  > cd install
  > ./install.sh

  Notice that you might need to install python-setuptools in the process


File Distribution
--------------
- *const.py*

  As it names, stores all the constant values. For example, the QCAT log id, RRC state id,
  link layer protocol id, and etc.

- *contextWorker.py*

  Stores all the functions that related to assign context information to each entry class, 
  i.e. RRC state, throughtput trace analysis, signal strength (RSCP and ECIO information)

- *crossLayerWorker.py* (new)

  Functions related to cross layer mapping algorithm. Able to correlate one TCP packets
  to multiple corresponding RLC PDUs. Include both uplink and downlink mapping for 3G.

- *DecodePcapFunc.py*

  A library that parse PCAP file and extract useful TCP/IP fields information.
  It was primarily used to support PCAPParser.py.

- *delayWorker.py* (new)
  
  Contains functions that related to TCP RTT and RLC OTA delay estimation.
  "calc_tcp_rtt" function could calculate TCP RTT for each TCP packet. However,
  it is possible that some TCP packet doesn't have an accurate RTT because of
  the accumulative ACK mechanism. "calc_rlc_rtt" esimates the OTA delay based on
  the most recent STATUS PDU.

- *flowAnalysis.py* (new)

  TCP flow analysis function. "extractTCPFlows" will extract all TCP flows in the
  QxDM logs, and return a list of Flow objects defined in Flow.py. "parse_http_fields"
  will parse the desired HTTP fields, i.e. Host, Referer, and etc.

- *Flow.py* (new)

  The Flow object class definition. It internally stores the flow's signature based
  on src/dst IP address and src/dst port number, relative positions in the QxDM trace, 
  properties related to HTTP, and the whole flow of TCP packets. Notice that you 
  need to call "getCrossLayerTrace" to get the whole QxDM from the time of 
  SYN packet time - const.FLOW_TIME_WIN until FIN packet time + const.FLOW_TIME_WIN.
  Notice that no extra IP packets are allowed in the cross_layer_trace.

- *largeDataProcess.sh* (new)

  Very useful script that could help you process large data that could not fit 
  into memory through input partition. The only requirement is that the output
  of each partition should be independent from each other.

- *lossWorker.py*

  UDP related analysis, i.e. loss analysis, UDP RTT calculation, and build up packet
  lookup table.

- *PCAPPacket.py*

  It was only used for mapping the timestamp between QCAT and converted PCAP file.
  Not very useful at this point.

- *PCAPParser.py*

  Use to analyze the server side dumped PCAP trace. Convert the trace into a hash table
  where the hash key could be either the hashed payload or the seq num. For UDP,
  the sequence number is manually injected. For TCP, the seq num is the one in its header.

- *PrintWrapper.py*

  Output interface to display statistical retransmission information, and other context 
  related information.

- *QCATEntry.py*

  I process the QCAT log file as three parts. First is the header information,
  which include timestamp and log entry ID. Then the detailed part could be parsed
  for context information, RLC sequence number, bit rate and other semantic information.
  The third part is the hex dump part, and it is useful for TCP/IP field parsing.

- *retxWorker.py*

  TCP and RLC layer retransmission calculation. For TCP, it is able to distinguish
  between the TCP Fast Retransmission and RTO analysis. For RLC, it is able to
  calculate the retransmission based on seq num duplication.

- *rootCauseWorker.py* (new)

  Root cause analysis utilize the cross-layer mapping to identify root causes for
  performance issues in the cellular network. A good example is "performance_analysis_for_browsing".
  It prints all the flow based performance metrics in both TCP layer and RRC/RLC layer.

- *traceAnalyzer.py*

  The core function of the tool. The basic workflow is that it will read data first.
  Then store them using internal data structure (QCATEntry class). Later assign context
  information and apply retransmission analysis. Finally, print useful results.

- *rrcTimerWorker.py*

  Validate the RRC state inferred timer for UMTS network. Primarily validate the
  FACH_PROMOTE and DCH_PROMOTE timer by counting the time interval between the last
  IP packet to the RRC state log.

- *Util.py*

  All the helper functions, such as calculate mean or median of a list, remove
  the duplicated protocol data entry in QCAT file, TCP/IP packet filtering based
  on the five tuples. 

- *validateWorker.py* (new)

  Contains all the validation functions. "check_mapping_feasibility_uniqueness"
  provides uniquesness analysis on cross-layer mapping to ensure the mapping
  accuracy. "validate_demotion_timer" generates the ground truth the demotion timers
  that could be compared with our RRC inference algorithm

Version Updates
--------------
# Version 0.6 (01/28/2014)
- Print basic cross-layer mapping and retransmission analysis in both layers
  > ./traceAnalyzer.py --retx_analysis --cross_mapping_detail -f QCAT_log_file_path -d up

- Print ground truth demotion timer value
  > ./traceAnalyzer.py -f QCAT_log_file_path --validate_demotion_timer

- Process large data
  > ./largeDataProcess.sh QCAT_log_file_path output_name num_of_partitions options(not include -f)
  i.e. ./largeDataProcess.sh input output 4 --root_cause_analysis http_analysis
    == ./traceAnalyzer.py -f input --root_cause_analysis http_analysis > output

# Version 0.1 (05/12/2013)
- Print retransmission ratio over different RRC state
  > ./traceAnalyzer.py -l QCAT_log_file_path -d up --srv_ip srver_ip_addr --retx_analysis --print_retx tcp_rto 

- Print cross layer map between RLC and RRC state
  > ./traceAnalyzer.py -l QCAT_log_file_path -d up --srv_ip srver_ip_addr --retx_analysis --cross_analysis

- Print throughput vs timestamps
  > ./traceAnalyzer.py -l QCAT_log_file_path --print_throughput

- Provide hints on source ip and destination ip (not guaranteed accurate)
  > ./traceAnalyzer.py -l QCAT_log_file_path -a 50
    
- Verify QCAT timer and PCAP timer (converted from QCAT file)
  > ./traceAnalyzer.py -m -l QCAT_log_file_path -p PCAP_file_path

- Validate the RLC fast retransmission mechanism
  > src/traceAnalyzer.py --retx_analysis --cross_analysis --dup_ack_threshold dup_ack_num --draw_percent draw_percent \
    -l QCAT_log_file_path -d up --srv_ip srver_ip_addr -p server_pcap_file

- Apply UDP loss analysis result
  > src/traceAnalyzer.py -l QCAT_log_file_path -p server_pcap_file -d up --srv_ip srver_ip_addr --loss_analysis -t udp

Tips
--------------
- We strongly recommend you include the filter options, i.e. -d and --srv_ip



   


