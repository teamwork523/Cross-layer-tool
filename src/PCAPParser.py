#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/07/2013
@Function	Parse the server side pcap file, and extract related information
"""

import sys, struct
from datetime import datetime
import DecodePcapFunc as dp
import const
import Util as util 

class PCAPParser:
    def __init__(self, filename, direction, protocol):
        self.filename = filename
        # each element contains a flow of packets
        self.packets = []
        self.global_header = []
        self.data = []
        self.is_uplink = (direction.lower() == "up")
        # Retransmission packets
        self.retx_pkts = []
        # Fast retransmission due to 3 DUP ACKs
        self.fast_retx_pkts = []
        # protocol could be either TCP or UDP
        self.protocol = protocol
        # A hash table to store the TCP packets
        # key = hashed TCP payload or TCP sequence number
        # value = list of TCP payload
        self.tcp_lookup_table = {}

        # A hash table to store UDP packets
        # key = hashed UDP payload or manually injected sequence number
        # value = list of UDP payload
        self.udp_lookup_table = {}
	
    def read_pcap(self):
        if self.filename:
            self.global_header, self.data = dp.read_Pcap(self.filename)
        else:
	        print >> sys.stderr, "Empty pcap filename"
	        sys.exit(1)
	
    ####################################################################
    ##################### Flow based Analysis ##########################
    ####################################################################
    def parse_pcap(self):
        if self.protocol == "tcp":
            # parse based on input length
            self.create_tcp_flows(const.LINK_HEADER_LEN[self.global_header["linktype"]])
        elif self.protocol == "udp":
            self.create_udp_trace(const.LINK_HEADER_LEN[self.global_header["linktype"]])
        elif self.protocol == "ip":
            self.create_ip_trace(const.LINK_HEADER_LEN[self.global_header["linktype"]])

    ####################################################################
    ######################## IP trace Analysis #########################
    ####################################################################
    # TODO: current build is only for validate QxDM trace
    # generate a IP trace
    def create_ip_trace(self, link_len):
        self.ip_trace = []
        for i in range(len(self.data)):
            new_ip = self.init_ip_pkt()
            # Notice that we store the converted Timestamp for debugging purpose
            new_ip["ts"] = util.convert_ts_in_human(dp.packet_time(self.data, i), year=True)
            new_ip["src_ip"] = dp.src_ip(self.data, i, link_len)
            new_ip["dst_ip"] = dp.dst_ip(self.data, i, link_len)
            new_ip["ip_header_len"] = dp.get_ip_header_len(self.data, i, link_len)
            new_ip["ip_len"] = dp.get_ip_len(self.data, i, link_len)
            new_ip["ip_raw_header"] = dp.raw_ip_header(self.data, i, link_len)
            new_ip["tlp_type"] = dp.protocol_type(self.data, i, link_len)
            if new_ip["tlp_type"] == const.TCP_ID:
                new_ip["tlp_raw_header"] = dp.get_raw_tcp_header(self.data, i, link_len)
            elif new_ip["tlp_type"] == const.UDP_ID:
                new_ip["tlp_raw_header"] = dp.get_raw_udp_header(self.data, i, link_len)
            self.ip_trace.append(new_ip)

    def init_ip_pkt(self):
        """
        Every IP packet contains
        1. Timestamp
        2. Src/dst ip
        3. IP header length
        4. IP packet length
        5. Transport layer protocol (tlp) type
        6. IP header raw data
        7. Transport layer header
        """
        return {"ts": None, "src_ip": None, "dst_ip": None, \
                "ip_header_len": None, "ip_len": None, "tlp_type": None, \
                "ip_raw_header": None, "tlp_raw_header": None}

    ####################################################################
    ####################### UDP trace Analysis #########################
    ####################################################################
    # generate a UDP trace
    def create_udp_trace(self, link_len):
        self.udp_trace = []
        for i in range(len(self.data)):
            new_datagram = self.init_udp_pkt()
            new_datagram["ts"] = dp.packet_time(self.data, i)
            # identical to TCP
            new_datagram["src_ip"] = dp.src_ip(self.data, i, link_len)
            new_datagram["dst_ip"] = dp.dst_ip(self.data, i, link_len)
            new_datagram["src_port"] = dp.src_port(self.data, i, link_len)
            new_datagram["dst_port"] = dp.dst_port(self.data, i, link_len)
            new_datagram["seg_size"] = dp.udp_seg_size(self.data, i, link_len)
            new_datagram["hashed_payload"] = util.md5_hash(dp.udp_payload(self.data, i, link_len))
            new_datagram["seq_num"] = dp.udp_seq_num(self.data, i, link_len)
            """            
            payload = dp.udp_payload(self.data, i, link_len)
            print "Payload with length %d:" % len(payload)
            print payload
            print "Hashed Result %s" % new_datagram["hashed_payload"]
            print "@" * 50
            """
            self.udp_trace.append(new_datagram)

    def init_udp_pkt(self):
        """
        Every UDP packet contain
        1. Timestamp
        2. Src/dst ip/port (4)
        3. segment size (length_in_header - header_len)
        4. hashed_payload (md5 hash of the payload)
        5. manually assigned seq_num at first 4 bytes in the payload
        """
        return {"ts": None, "src_ip": None, "dst_ip": None, \
				"src_port": None, "dst_port": None, \
                "seg_size": None, "hashed_payload": None, \
                "seq_num": None}

    # filter based on condition
    def filter_based_on_cond(self, kw, cond):
        new_trace = []
        for datagram in self.udp_trace:
            if kw == "srv_ip":
                # filter both src_ip and dst_ip for srv_ip
                if datagram["src_ip"] == cond or datagram["dst_ip"] == cond:
                    new_trace.append(datagram)
            elif datagram[kw] == cond:
                new_trace.append(datagram)
        self.udp_trace = new_trace

    # create UDP hashed table with options of hashed payload or seq_num
    # @input:
    #   1. options: "hash" or "seq"
    def build_udp_lookup_table(self, hash_type):
        udp_keying_field = None
        if hash_type == "hash":
            udp_keying_field = "hashed_payload"
        elif hash_type == "seq":
            udp_keying_field = "seq_num"
        else:
            print >> sys.stderr, "ERROR: UDP hashed type not supported!"

        for datagram in self.udp_trace:
            if not self.udp_lookup_table.has_key(datagram[udp_keying_field]):
                self.udp_lookup_table[datagram[udp_keying_field]] = [datagram]
            else:
                self.udp_lookup_table[datagram[udp_keying_field]].append(datagram)

    ####################################################################
	####################### TCP Flow Analysis ##########################
	####################################################################
    def create_tcp_flows(self, link_len):
        local_flow = []
        trace_index = 0

        # parse the data into list of flow of packets
        for i in range(len(self.data)):
            new_packet = self.init_tcp_pkt()
            new_packet["ts"] = dp.packet_time(self.data, i)
            new_packet["src_ip"] = dp.src_ip(self.data, i, link_len)
            new_packet["dst_ip"] = dp.dst_ip(self.data, i, link_len)
            new_packet["src_port"] = dp.src_port(self.data, i, link_len)
            new_packet["dst_port"] = dp.dst_port(self.data, i, link_len)
            new_packet["flags"]["urg"] = dp.tcp_flag_bit(self.data, i, link_len, 5)
            new_packet["flags"]["ack"] = dp.tcp_flag_bit(self.data, i, link_len, 4)
            new_packet["flags"]["psh"] = dp.tcp_flag_bit(self.data, i, link_len, 3)
            new_packet["flags"]["rst"] = dp.tcp_flag_bit(self.data, i, link_len, 2)
            new_packet["flags"]["syn"] = dp.tcp_flag_bit(self.data, i, link_len, 1)
            new_packet["flags"]["fin"] = dp.tcp_flag_bit(self.data, i, link_len, 0)
            new_packet["ack_num"] = dp.ack_num(self.data, i, link_len)
            new_packet["seq_num"] = dp.sequence_num(self.data, i, link_len)
            new_packet["win_size"] = dp.window_size_server(self.data, i, link_len)	# size match
            new_packet["seg_len"] = dp.tcp_seg_size(self.data, i, link_len)
            new_packet["hashed_payload"] = util.md5_hash(dp.udp_payload(self.data, i, link_len))
            new_packet["trace_index"] = trace_index

	        # check new flow
            if new_packet["flags"]["syn"] and not new_packet["flags"]["ack"] and local_flow:
                self.packets.append(local_flow)
                local_flow = [new_packet]
                trace_index += 1
            else:
                local_flow.append(new_packet)

        if local_flow:
            self.packets.append(local_flow)

    def init_tcp_pkt(self):
        # Each packet should contain:
        # 1. timestamp
        # 2. src / dst ip
        # 3. src / dst port
        # 4. TCP flags (use another dict to record)
        # 5. ACK / SEQ number
        # 6. Window size
        # 7. hashed payload using uniformed hash function
        # 8. trace index keeps track of the position in the trace
        return {"ts": None, "src_ip": None, "dst_ip": None, \
                "src_port": None, "dst_port": None, \
                "flags": {"urg": None, "ack": None, "psh": None, "rst": None, "syn":None, "fin": None},\
                "ack_num": None, "seq_num": None, "win_size": None, "seg_len": None, \
                "throughput": None, "hashed_payload": None, "trace_index": None}

    # create TCP hashed table with options of seq_num or hashed payload
    # @input:
    #   1. options: "hash" or "seq"
    def build_tcp_lookup_table(self, hash_type):
        tcp_keying_field = None
        if hash_type == "hash":
            tcp_keying_field = "hashed_payload"
        elif hash_type == "seq":
            tcp_keying_field = "seq_num"
        else:
            print >> sys.stderr, "ERROR: TCP hashed type not supported!"

        for trace in self.packets:
            for packet in trace:
                if not self.tcp_lookup_table.has_key(packet[tcp_keying_field]):
                    self.tcp_lookup_table[packet[tcp_keying_field]] = [packet]
                else:
                    self.tcp_lookup_table[packet[tcp_keying_field]].append(packet)

	def retx_analysis(self):
		# Match the retransmission packets base on sequence number
		for flow in self.packets:
			local_retx_li = []
			local_fast_retx_li = []
			base_num, clt_ip, srv_ip, start_ts = self.__extract_trace_begin_info(flow)
			flow_start_index = 0
			# keep a list of previous packets which doesn't include retx and fast retx packets
			priv_pkts = []
			# find the beginning of the trace
			for index in range(len(flow)):
				# Ignore 3-way handshake by start analysis after SYN/SYN-ACK/ACK
				if flow[index]["seg_len"] == 0:
					if (self.is_uplink and flow[index]["seq_num"] == base_num + 1) or \
					   (not self.is_uplink and flow[index]["seq_num"] == base_num):
						flow_start_index = index + 1
						break
			
			# real flow analysis
			for i in range(flow_start_index, len(flow)):
				# TODO: Find a better way to handle init of TCP connection and end of TCP connection
				#if flow[i]["flags"]["syn"]:
					#continue
				# Wireshark: fast retx should be identified first
				"""
				if self.__check_fast_retx(flow[i], flow[flow_start_index:i], clt_ip, srv_ip):
					local_fast_retx_li.append(flow[i])
				elif self.__check_retx(flow[i], flow[flow_start_index:i], clt_ip, srv_ip):
					local_retx_li.append(flow[i])
				"""
				if self.__check_fast_retx(flow[i], priv_pkts, clt_ip, srv_ip):
					local_fast_retx_li.append(flow[i])
				elif self.__check_retx(flow[i], priv_pkts, clt_ip, srv_ip):
					local_retx_li.append(flow[i])
				else:
					priv_pkts.append(flow[i])
			if local_retx_li:
				self.retx_pkts.append(local_retx_li)
			if local_fast_retx_li:
				self.fast_retx_pkts.append(local_fast_retx_li)

	def throughput_analysis(self):
		# Assume that we are on the server side and 3-way handshke initialize on from the client side
		# Uplink trace
		# 1. Same source ip, use SEQ number - SEQ of first (SYN)
		# 2. Diff source ip, use ACK number - SEQ of first (SYN) (more accurate)
		# Downlink
		# 1. Same source ip, use ACK - SEQ of first (SYN, ACK) (more accurate)
		# 2. Diff source ip, use SEQ - SEQ of first (SYN, ACK)
		if not self.packets:
			print "Not ready for throughput analysis, need to parse the packets first"
			return
		
		for flow in self.packets:
			base_num, clt_ip, srv_ip, start_ts = self.__extract_trace_begin_info(flow)
			for packet in flow:
				if self.is_uplink:
					if packet["src_ip"] == clt_ip and packet["dst_ip"] == srv_ip:
						packet["throughput"] = self.__calThroughput(packet["seq_num"] - base_num, packet["ts"] - start_ts)
					if packet["dst_ip"] == clt_ip and packet["src_ip"] == srv_ip:
						packet["throughput"] = self.__calThroughput(packet["ack_num"] - base_num, packet["ts"] - start_ts)
				else:
					if packet["src_ip"] == clt_ip and packet["dst_ip"] == srv_ip:
						packet["throughput"] = self.__calThroughput(packet["ack_num"] - base_num, packet["ts"] - start_ts)
					if packet["dst_ip"] == clt_ip and packet["src_ip"] == srv_ip:
						packet["throughput"] = self.__calThroughput(packet["seq_num"] - base_num, packet["ts"] - start_ts)
				if packet["throughput"] > const.UPPER_BOUND_TP:
					raise Exception("TP result %f larger than %f at %s" % (packet["throughput"], const.UPPER_BOUND_TP, \
									 util.convert_ts_in_human(packet["ts"])))
					
    def debug(self):
        if self.protocol == "tcp":
            """
            print "Number of flows: %d" % (len(self.packets))
            print "~~~~~~~~~~~~ Retx ~~~~~~~~~~~~~~~~"
            self.printFlowsWithTime(self.retx_pkts)
            print "~~~~~~~~~~~~ Fast retx ~~~~~~~~~~~~~~~"
            self.printFlowsWithTime(self.fast_retx_pkts)
            """
            print "TCP lookup table:"
            print self.tcp_lookup_table
        elif self.protocol == "udp":
            print "UDP lookup table: "
            print self.udp_lookup_table
            """
            for i in self.udp_trace:
                if i["seq_num"]:
                    print "Sequence Number is %d" % (i["seq_num"])
            """

	####################################################################
	####################### Helper Function ############################
	####################################################################
	# Extract the base number for calculation
	# @return (seq_num, clt_ip, srv_ip, ts )
	def __extract_trace_begin_info(self, singleFlow):
		# based on measurement direction, we could log the in two directions
		for pkt in singleFlow:
			if pkt["flags"]["syn"] and not pkt["flags"]["ack"] and self.is_uplink:
				return (pkt["seq_num"], pkt["src_ip"], pkt["dst_ip"], pkt["ts"])
			if pkt["flags"]["syn"] and pkt["flags"]["ack"] and not self.is_uplink:
				return (pkt["seq_num"], pkt["dst_ip"], pkt["src_ip"], pkt["ts"])
		raise Exception("No proper flow beginning packet found!")
	
	# calculate the throughput		
	def __calThroughput (self, payload, time):
		if time <= 0:
			return 0
		else:
			return payload / time
	
	# check retransmission of packets based on current pkt's seq_num
	def __check_retx (self, pkt, prv_pkts, clt_ip, srv_ip):
		# check direction
		if (self.is_uplink and (pkt["src_ip"] != clt_ip or pkt["dst_ip"] != srv_ip)) or \
		   (not self.is_uplink and (pkt["src_ip"] != srv_ip or pkt["dst_ip"] != clt_ip)) or \
		   pkt["seg_len"] <= 0:
		   	return False
		   
		# Most recent comes first
		for p in prv_pkts[::-1]:
			if ((self.is_uplink and clt_ip == p["src_ip"] and srv_ip == p["dst_ip"]) or \
			   (not self.is_uplink and srv_ip == p["src_ip"] and clt_ip == p["dst_ip"])):
			   	# fast determination by detecting seq_num increase
			   	if pkt["seq_num"] > p["seq_num"]:
			   		return False
			   	# Wireshark: the retransmission gap is less than 3ms
			   	elif pkt["seq_num"] == p["seq_num"] and pkt["ts"] - p["ts"] > const.RETX_GAP:
					return True
		return False
		
	# check fast retransmission of packets based on current pkt's seq_num
	def __check_fast_retx(self, pkt, prv_pkts, clt_ip, srv_ip):
		ack_count = 0
		last_ack = None
				
		# check direction
		if (self.is_uplink and (pkt["src_ip"] != clt_ip or pkt["dst_ip"] != srv_ip)) or \
		   (not self.is_uplink and (pkt["src_ip"] != srv_ip or pkt["dst_ip"] != clt_ip)) or \
		   pkt["seg_len"] <= 0:
		   	return False
		   	
		# Most recent comes first
		for ack in prv_pkts[::-1]:
			# packet seq_num matches ACK's ack_num
			if ((self.is_uplink and clt_ip == ack["dst_ip"] and srv_ip == ack["src_ip"]) or \
			   (not self.is_uplink and srv_ip == ack["dst_ip"] and clt_ip == ack["src_ip"])) and \
			   ack["seg_len"] == 0:
			   	# fast determination by detecting small ack number
			   	if pkt["seq_num"] > ack["ack_num"]:
			   		return False
			   	elif pkt["seq_num"] == ack["ack_num"]:
			   		if not ack_count:
			   			last_ack = ack
					ack_count += 1
				# Wireshark: the current packet should happen within 20 ms of the last dup ACK
				if last_ack:
					if pkt["ts"] - last_ack["ts"] > const.LAST_ACK_GAP:
						return False
					last_ack = None
			if ack_count >= const.FAST_RETX_COUNT:
				return True
		return False

	def printFlowsWithTime(self, flows):
		for flow in flows:
			print "#" * 50
			for i in flow:
				self.printPkt(i)
			
	def printPkt(self, i):
		print "%s\t%s\t%s\t%s\t%s\t%d" % (util.convert_ts_in_human(i["ts"]), i["src_ip"], i["dst_ip"], hex(i["seq_num"]), hex(i["ack_num"]), i["seg_len"])
				
# Sample of usage	
"""
def main():
    pcap = PCAPParser(sys.argv[1], "up", "ip")
    pcap.read_pcap()
    pcap.parse_pcap()
    # UDP example
    #pcap.filter_based_on_cond("dst_ip", "141.212.113.208")
    #pcap.build_udp_lookup_table("seq")
    # TPC example
    #pcap.build_tcp_lookup_table("seq")
    # pcap.throughput_analysis()
    # pcap.retx_analysis()
    #pcap.debug()
	
if __name__ == "__main__":
    main()	
"""	
