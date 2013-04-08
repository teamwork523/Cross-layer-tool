The project is a tool that parse QCAT and apply post data analysis.

Author
--------------
- Haokun Luo (haokun@umich.edu)


File Distribution
--------------
- *traceAnalyzer.py*
  The core function of the tool. The basic work flow is that it will read data first.
  Then store them using internal data structure (QCATEntry class). Later assign context
  information and apply retransmission analysis. Finally, print useful results.

  WARNING: options could conflict with each other. Please follow the sample usage section

- *const.py*
  As it names, stores all the constant values. For example, the QCAT log id, RRC state id,
  link layer protocol id, and etc.

- *contextWorker.py*
  Stores all the functions that related to assign context information to each entry class, 
  i.e. RRC state, thoughtput trace analysis, signal strength (RSCP and ECIO information)

- *DecodePcapFunc.py*
  A library that parse PCAP file and extract useful TCP/IP fields information.
  It was primarily used to support PCAPParser.py.

- *PCAPPacket.py*
  It was only used for mapping the time stamp between QCAT and converted PCAP file.
  Not very useful at this point.

- *PCAPParser.py*
  Use to analyze the server side dumped PCAP trace. The mapping between the server side
  trace with client trace is still under progress.

- *PrintWrapper.py*
  Output interface to display statistical retransmission information, and other context 
  related information.

- *QCATEntry.py*
  I process the QCAT log file as three parts. First is the header information,
  which include timestamp and log entry ID. Then the detailed part could be parsed
  for context information, RLC sequence number, bit rate and other semantic information.
  The third part is the hex dump part, and it is useful for TCP/IP field parsing.

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

- Provide hints on source ip and destination ip (not gaurentee accurate)
  > ./traceAnalyzer.py -l QCAT_log_file_path -a 50
    
- Verify QCAT timer and PCAP timer (converted from QCAT file)
  > ./traceAnalyzer.py -m -l QCAT_log_file_path -p PCAP_file_path


Notice
--------------
- My tool prefers uni-direction trace



   
