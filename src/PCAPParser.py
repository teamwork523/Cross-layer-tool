#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   03/07/2013
@Function	Parse the pcap file, and extract related information
"""

import sys, struct
import DecodePcapFunc as dp
import const

class PCAPParser:
	def __init__(self, filename):
		self.filename = filename
		self.packets = []
		self.read_pcap()
		
		
	def read_pcap(self):
		print "Read from PCAP"
		if self.filename:
			self.global_header, self.data = dp.read_Pcap(self.filename)
			if self.global_header["linktype"] == const.LINKTYPE_ETHERNET:
				self.parse_ethernet()
			elif self.global_header["linktype"] == const.LINKTYPE_RLC:
				self.parse_rlc()
		else:
			print >> sys.stderr, "Empty pcap filename"
			sys.exit(1)
	
	####################################################################
	############################ Ethernet ##############################
	####################################################################
	def parse_ethernet(self):
		self.create_flows()
		
	def create_flows(self):
		local_flow = []
		# parse the data into list of flow of packets
		for i in range(len(self.data)):
			new_packet = self.init_pkt()
			new_packet["ts"] = dp.packet_time(self.data, i)
			new_packet["src_ip"] = dp.src_ip(self.data, i, const.ETHERNET_HEADER)
			new_packet["dst_ip"] = dp.dst_ip(self.data, i, const.ETHERNET_HEADER)
			new_packet["src_port"] = dp.src_port(self.data, i, const.ETHERNET_HEADER)
			new_packet["dst_port"] = dp.dst_port(self.data, i, const.ETHERNET_HEADER)
			new_packet["flags"]["urg"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 5)
			new_packet["flags"]["ack"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 4)
			new_packet["flags"]["psh"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 3)
			new_packet["flags"]["rst"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 2)
			new_packet["flags"]["syn"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 1)
			new_packet["flags"]["fin"] = dp.tcp_flag_bit(self.data, i, const.ETHERNET_HEADER, 0)
			new_packet["ack_num"] = dp.ack_num(self.data, i, const.ETHERNET_HEADER)
			new_packet["seq_num"] = dp.sequence_num(self.data, i, const.ETHERNET_HEADER)
			new_packet["win_size"] = dp.window_size_server(self.data, i, const.ETHERNET_HEADER)	# size match
			
			# check new flow
			if new_packet["flags"]["syn"] and not new_packet["flags"]["ack"]:
				self.packets.append(local_flow)
				local_flow = []
			else:
				local_flow.append(new_packet)
	
	def init_pkt(self):
		# Each packet should contain:
		# 1. timestamp
		# 2. src / dst ip
		# 3. src / dst port
		# 4. TCP flags (use another dict to record)
		# 5. ACK / SEQ number
		# 6. Window size
		return {"ts": None, "src_ip": None, "dst_ip": None, \
				"src_port": None, "dst_port": None, \
				"flags": {"urg": None, "ack": None, "psh": None, "rst": None, "syn":None, "fin": None},
				"ack_num": None, "seq_num": None, "win_size": None}
	
	def retx_analysis(self):
		# TODO: finish this part
		pass
	
	####################################################################
	############################# RLC ##################################
	####################################################################
	# TODO: this type is converted from QCAT log file
	def parse_rlc(self):
		pass
		

def main():
	pcap = PCAPParser(sys.argv[1])
	pcap.parse_ethernet()
	print pcap.packets
	
if __name__ == "__main__":
    main()
	
			
			
