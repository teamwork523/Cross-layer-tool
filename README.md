The project is a tool that parse QCAT logs and apply post data analysis.

Author
--------------
- Haokun Luo (haokun@umich.edu)


File Distribution
--------------
- *const.py*

  As it names, stores all the constant values. For example, the QCAT log id, RRC state id,
  link layer protocol id, and etc.

- *contextWorker.py*

  Stores all the functions that related to assign context information to each entry class, 
  i.e. RRC state, throughtput trace analysis, signal strength (RSCP and ECIO information)

- *crossLayerWorker.py*

  Functions related to cross layer mapping algorithm. Able to correlate one TCP packets
  to multiple corresponding RLC PDUs. It also include the cost-benefit analysis of
  fast retransmission mechanism.

- *DecodePcapFunc.py*

  A library that parse PCAP file and extract useful TCP/IP fields information.
  It was primarily used to support PCAPParser.py.

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


Sample Usage
--------------
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



   


