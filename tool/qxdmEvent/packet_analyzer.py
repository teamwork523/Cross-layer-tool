#!/usr/bin/python

import re

def extractFirst(s, line):
	'''XXX make global'''
	
	m = re.findall(s, line)
	if m:
		return m[0]
	return None

def extractAll(s, line):
	m = re.findall(s, line)
	if m:
		return m
		

class PacketAnalyzer():
	(FRAME, IP, PROTOCOL) = range(3)

	def __init__(self, target_ip):
		self.target_ip = target_ip
		self.all_packets = []
		self.all_test_timings = []
		self.cur_packet = None
		self.cur_test = None
		self.time = 0

	def add_line(self, line):
		if line.startswith("Frame"):
			if self.cur_packet != None and self.cur_packet.is_candidate:
				self.all_packets.append(self.cur_packet)
			self.cur_packet = Packet()
			self.cur_packet.size = extractFirst(r"\d+ bytes", line)[:-6]
			
		elif line.strip().startswith("Arrival Time:"):
			self.cur_packet.time = self.getTime(line, self.cur_packet)
		elif line.startswith("Internet Protocol Version"):
			result = extractAll(r"\d+[.]\d+[.]\d+[.]\d+", line)
			if result != None and len(result) == 4:
				self.cur_packet.src = result[1]
				self.cur_packet.dst = result[3]
		elif line.startswith("User Datagram Protocol") and "50000" in line:
			self.cur_packet.is_candidate = True

	def printall(self):
		for p in self.all_packets:
			p.printme_simple()

        def getTime(self, line, packet):
                match = re.search('(\d+):(\d+):(\d+)[.](\d+)', line)
                packet.time = 0
                if match:
                        packet.time += int(match.group(4))
                        packet.time += int(match.group(3)) * 1000
                        packet.time += int(match.group(2)) * 60 * 1000
                        packet.time += int(match.group(1)) * 3600 * 1000
		self.time = packet.time
		return self.time


	def find_timings(self):
		last_time = None
		last_time_is_src = False
		for p in self.all_packets:
			if p.isTestPacket(self.target_ip):
				if p.src == self.target_ip:
					if self.cur_test != None and self.cur_test.end_time != None:
						self.all_test_timings.append(self.cur_test)
					self.cur_test = TestPacket(last_time, p.time)
					last_time_is_src = True
				elif self.cur_test != None and last_time_is_src:
					self.cur_test.end_time = p.time	
					last_time_is_src = False
				#else:
					#last_time_is_src = False

				last_time = p.time

	def output_timing_results(self):
		for item in self.all_test_timings:
			item.printme()

class Packet():
	def __init__(self):
		self.size = None
		self.src = None
		self.dst = None
		self.time = 0 
		self.is_candidate = False

	def printme(self):
		if self.is_candidate:
			print "********",
		print self.time, self.src, self.dst, self.size

	def printme_simple(self):	
		print self.time, self.src, self.dst, self.size
	
	def isTestPacket(self, target_ip):
		if not self.is_candidate:
			return False
#		if self.src != target_ip and self.dst != target_ip:
#			return False
		return True

class TestPacket():
	def __init__(self, prior_time, begin_time):
		self.prior_time = prior_time
		self.begin_time = begin_time
		self.end_time = None
	
	def isComplete(self):
		return self.end_time != None
	
	def printme(self):
		if self.end_time != None:
			try:
				self.prior_time = float(self.prior_time)
				self.begin_time = float(self.begin_time)
				self.end_time = float(self.end_time)
				print self.begin_time - self.prior_time,
				print self.end_time -self.begin_time
			except:
				return
