#!/usr/bin/python

import sys, re, operator
import robustnetLib, packet_analyzer
from collections import Counter

# TODO:
#	Total repeats of all
# 	Interferers between pairs
#	Port to 4G

event_list = ["EVENT_LTE_BSR_SR_REQUEST", \
	"EVENT_LTE_CM_OUTGOING_MSG", \
	"EVENT_LTE_EMM_INCOMING_MSG", \
	"EVENT_LTE_EMM_OTA_OUTGOING_MSG", \
	"EVENT_LTE_EMM_OUTGOING_MSG", \
	"EVENT_LTE_EMM_TIMER_EXPIRY", \
	"EVENT_LTE_EMM_TIMER_START", \
	"EVENT_LTE_ESM_OUTGOING_MSG", \
	"EVENT_LTE_MAC_RESET", \
	"EVENT_LTE_MAC_TIMER", \
	"EVENT_LTE_ML1_PHR_REPORT", \
	"EVENT_LTE_RACH_ACCESS_RESULT", \
	"EVENT_LTE_RACH_ACCESS_START", \
	"EVENT_LTE_RACH_RAID_MATCH", \
	"EVENT_LTE_REG_INCOMING_MSG", \
	"EVENT_LTE_REG_OUTGOING_MSG", \
	"EVENT_LTE_RRC_DL_MSG", \
	"EVENT_LTE_RRC_NEW_CELL_IND", \
	"EVENT_LTE_RRC_OUT_OF_SERVICE", \
	"EVENT_LTE_RRC_PAGING_DRX_CYCLE", \
	"EVENT_LTE_RRC_SECURITY_CONFIG", \
	"EVENT_LTE_RRC_STATE_CHANGE", \
	"EVENT_LTE_RRC_STATE_CHANGE_TRIGGER", \
	"EVENT_LTE_RRC_TIMER_STATUS", \
	"EVENT_LTE_RRC_UL_MSG", \
	"EVENT_LTE_TIMING_ADVANCE"]

lte_states = ["Inactive", "Idle Not Camped", "Idle Camped", "Connecting", "Connected", "Closing"]

class Event:
	all_events = {}	
	current_event = None
	last_state = None
	distinct_events = set(["PACKET_SENT", "PACKET_RCV"])

	def __init__(self):
		self.time = 0
		self.event = None
		self.before_state = None
		self.after_state = None
		self.subtype = ""
		self.secondary_attributes = {}

	def addNewLine(self, line):
		if line.startswith("2013"):
			#if Event.current_event != None and Event.current_event.event != None:
			#	Event.current_event.printme()
			self.__saveEvent()	
			Event.current_event = Event()
			Event.current_event.__getEvent(line)
		Event.current_event.__getTime(line)
		Event.current_event.__getStateChange(line)
		Event.current_event.__getSecondary(line)

	def addUpperLayerPackets(self, filename):
		f = open(filename)
		ip = "141.212.113.208"
		pa = packet_analyzer.PacketAnalyzer(ip)
		for line in f:
			pa.add_line(line)
		for packet in pa.all_packets:
			Event.current_event = Event()
			Event.current_event.time = packet.time
			if not packet.is_candidate:
				Event.current_event.event = "PACKET_OTHER"
			elif packet.dst == ip:
				Event.current_event.event = "PACKET_SENT"
			else:
				Event.current_event.event = "PACKET_RCV"
			packet.printme_simple()
			assert(Event.current_event.time != None)
			if Event.current_event.time in Event.all_events:
				Event.all_events[Event.current_event.time].append(Event.current_event)
			else:
				Event.all_events[Event.current_event.time] = [Event.current_event]
					

	def __getTime(self, line):
		match = re.search('(\d+):(\d+):(\d+)[.](\d+)', line)
		if match:
			self.time += int(match.group(4))
			self.time += int(match.group(3)) * 1000
			self.time += int(match.group(2)) * 60 * 1000
			self.time += int(match.group(1)) * 3600 * 1000

	def __getEvent(self, line):
		match = re.findall('[A-Z]+(?:_+[A-Z0-9]+)+', line)	
		if len(match) > 0:
			self.event = match[0]
			if self.event == "EVENT_RRC_MESSAGE_RECEIVED":
				self.subtype = " <---- "
			elif self.event == "EVENT_RRC_MESSAGE_SENT":
				self.subtype = " ----> " 



	def __getSecondary(self, line):
		if "Payload String" in line and self.event != None:
			if self.event == "EVENT_RRC_MESSAGE_RECEIVED" or self.event == "EVENT_RRC_MESSAGE_SENT":
				self.event = line.split()[-1]
				# TODO get channel
				return

			match_string = None
			match_labels = None
			if self.event == "EVENT_LTE_RRC_TIMER_STATUS":
				match_string = ["Timer Name = ([A-Za-z0-9 _]+), Timer Value = ([0-9]+), Timer State = ([A-Za-z0-9 _]+)"]
				match_labels = ("Timer Name", "Timer Value", "Timer State")
			elif self.event == "EVENT_LTE_EMM_TIMER_START" or \
					self.event == "EVENT_LTE_EMM_TIMER_EXPIRY":	
				match_string = ["Timer ID = TIMER (T[0-9]+)", "(Timer ID = [0-9]+)"]
				match_labels = ("Timer ID",)
			elif self.event == "RRC_STATE_CHANGE_TRIGGER":	
				match_string = ["RRC State Change Trigger = ([A-Za-z0-9 _]+)"]
				match_labels = ("Trigger",)
			elif self.event == "EVENT_LTE_EMM_OUTGOING_MSG" or \
					self.event == "EVENT_LTE_EMM_OTA_OUTGOING_MSG" or \
					self.event == "EVENT_LTE_ESM_OUTGOING_MSG" or \
					self.event == "EVENT_LTE_EMM_INCOMING_MSG" or \
					self.event == "EVENT_LTE_CM_OUTGOING_MSG":	
				match_string = ["Message ID = ([A-Za-z0-9 _]+)"]
				match_labels = ("Message ID",)
			elif self.event == "EVENT_LTE_RRC_UL_MSG":	
				match_string = ["Message Type = ([A-Za-z0-9 _]+)"]
				match_labels = ("Message Type",)
			elif self.event == "EVENT_LTE_RACH_ACCESS_START":	
				match_string = ["RACH Cause = ([A-Za-z0-9 _]+), RACH Contention = ([A-Za-z0-9 _]+)"]
				match_labels = ("RACH Cause", "RACH Contention")
			elif self.event == "EVENT_LTE_RRC_PAGING_DRX_CYCLE":	
				match_string = ["DRX Cycle = ([0-9]+)"]
				match_labels = ("DRX_CYCLE",)
			elif self.event == "EVENT_LTE_RACH_RAID_MATCH":	
				match_string = ["Match = ([0-9]+)"]
				match_labels = ("Match",)
			elif self.event == "EVENT_LTE_TIMING_ADVANCE":	
				match_string = ["Timer Value = ([0-9]+), Timing Advance = ([0-9]+)"]
				match_labels = ("Timer Value", "Timing Advance")
			elif self.event == "EVENT_LTE_MAC_TIMER":
				match_string = ["Timer type = ([A-Za-z0-9 _]+), Action = ([A-Za-z0-9 _]+)"]
				match_labels = ("Timer type", "Action")
			elif self.event == "EVENT_LTE_MAC_RESET":
				match_string = ["Cause = ([A-Za-z0-9 _]+)"]
				match_labels = ("Cause",)
			elif self.event == "EVENT_LTE_RACH_ACCESS_RESULT":	
				match_string = ["Result = ([A-Za-z0-9 _]+)"]
				match_labels = ("Result",)
			elif self.event == "EVENT_LTE_RRC_UL_MSG" or \
					self.event == "EVENT_LTE_RRC_DL_MSG":	
				match_string = ["Channel Type = ([A-Za-z0-9 _]+), Message Type = ([A-Za-z0-9 _]+)"]
				match_labels = ("Channel Type", "Message Type")
			elif self.event == "EVENT_LTE_ML1_PHR_REPORT":	
				match_string = ["Power Headroom = ([-A-Za-z0-9 _]+), PHR Trigger = ([A-Za-z0-9 _]+)"]
				match_labels = ("Power Headroom", "PHR Trigger")
			elif self.event == "EVENT_LTE_BSR_SR_REQUEST":
				match_string = ["Is BSR Timer Expired = ([0-9]+), Is Higher Priority Data Arrial = ([0-9]+), Is Retx BSR Timer Expired = ([0-9]+), Is Request To Include BSR Report = ([0-9]+), Is Request To Send SR = ([0-9]+)"]
				match_labels = ("Is BSR Timer Expired", \
						"Is Higher Priority Data Arrial", \
						"Is Retx BSR Timer Expired", \
						"Is Request To Include BSR Report", \
						"Is Request To Send SR")
			elif self.event == "EVENT_LTE_RRC_SECURITY_CONFIG":
				match_string = ["Status = ([A-Za-z0-9 _]+)"]
				match_labels = ("Status",)
			elif self.event == "EVENT_LTE_RRC_NEW_CELL_IND":
				match_string = ["Cause = ([A-Za-z0-9 _]+), Frequency = ([0-9]+), Cell ID = ([0-9]+)"]
				match_labels = ("Cause", "Frequency", "Cell ID")

			if match_string != None and match_labels != None:
				for s in match_string:
					match = re.search(s, line)
					if match == None:
						continue
					for i in range(len(match.groups())):
						if i < len(match_labels):
							self.secondary_attributes[match_labels[i]] = match.group(i+1)
						else:
							print "ERROR on ", line
					break
				if match == None:
					print "ERROR on ", line, self.event

		
				

			

	def __getStateChange(self, line):
		if self.event== "EVENT_LTE_RRC_STATE_CHANGE" and line.startswith("Payload String"):
			for state in lte_states:
				if state in line:
					self.after_state = state
					break
			self.before_state = Event.last_state
			Event.last_state = self.after_state
		if self.event == "EVENT_WCDMA_RRC_STATE" and line.startswith("Payload String = Previous state:"):
			match = re.search('([A-Z]+_[A-Z]+).*([A-Z]+_[A-Z]+)', line)
			if match:
				self.before_state = match.group(1)
				self.after_state = "CEL" + match.group(2)
			match = re.search('Previous state: ([A-Za-z_]+), New state: ([A-Za-z_]+)', line)
			if match:
				self.before_state = match.group(1)
				self.after_state = match.group(2)
				
	def __saveEvent(self):
		if Event.current_event == None or Event.current_event.event == None:
			return	
#		Event.current_event.__print()
		Event.distinct_events.add(Event.current_event.event)
		if Event.current_event.time in Event.all_events:
			Event.all_events[Event.current_event.time].append(Event.current_event)
		else:
			Event.all_events[Event.current_event.time] = [Event.current_event]

	def printme(self):
		print self.time, "\t", self.after_state, "\t", self.event, self.subtype
		for k, v in self.secondary_attributes.iteritems():
			print "\t", k, ":", v


# questions to answer:
#	What events are between them
#	we list all unexpected events, including system stuff
class Transition():
	all_transitions = []
	last_transition = None
	#filter_meta = ["sys_info", "measure_report", "measure_control", "EVENT_WCDMA_RRC_STATE", "mobility_confirm", "cell_update", "cell_update_confirm"] 
	filter_meta = []

#["radio_reconfig", "radio_reconfig_complete", "rlc_config", "cell_update", "update_confirm"]

	def __create_dict(self, lists, d = False):
		retval = {}
		for v in Event.distinct_events:
			if lists:
				retval[v] = []
			elif d:
				retval[v] = {}
			else:
				retval[v] = 0
		return retval 

	def __init__(self, state, time):
		self.state = state
		self.begin_time = time
		self.end_time = 0
		self.transition = None
		self.after_transition = None
		self.between = []
#		self.time_to_reach_first = { "radio_reconfig":0, "radio_reconfig_complete":0, "rlc_config":0, "phy_reconfig":0, "phy_reconfig_complete":0}
		self.time_to_reach_first = self.__create_dict(False)
		self.time_to_reach_last = self.__create_dict(False)
		self.attributes_first = self.__create_dict(False, d=True)
		self.attributes_last = self.__create_dict(False, d=True)
		self.duplicates_first = self.__create_dict(False)
		self.duplicates_last = self.__create_dict(False)
		interferers = {}	

	def update(self, event):
		if event.after_state != self.state and not event.event.startswith("PACKET"):
			self.after_transition=  str(event.before_state) + " -> " + str(event.after_state)
			self.end_time = event.time
			return False

		if event.event not in Transition.filter_meta:
			if len(self.between) > 0 and self.between[-1][0] == event.event:
				self.between[-1][1] += 1
			else:
				self.between.append([event.event, 1, event])
		if not event.event.startswith("PACKET"):
			self.state = event.after_state
			if self.transition == None:
				self.transition = str(event.before_state) + " -> " + str(event.after_state)
			
		return True

	def find_stats_and_finalize(self, event):
		for item in self.between:
			subtype = item[0]
			count = item[1]
			event = item[2]
			if subtype in self.time_to_reach_first and self.time_to_reach_first[subtype] == 0:
				self.time_to_reach_first[subtype] = event.time - self.begin_time
				# TODO update
				self.duplicates_first[subtype] = count
				self.attributes_first[subtype] = event.secondary_attributes
			event.printme()
#			print "Finalizing!", self.end_time, event.time
			self.time_to_reach_last[subtype] = self.end_time - event.time
			self.duplicates_last[subtype] = count
			self.attributes_last[subtype] = event.secondary_attributes


	def __merge_attributes(self, new_attributes, attribute_dict, event):
		for k, v in new_attributes.iteritems():
			if k not in attribute_dict[event]:
				attribute_dict[event][k] = []
			try:
				v = int(v)
			except:
				pass
			attribute_dict[event][k].append(v)

	def __print_attributes(self, attribute_dict, event):
		for k, v in attribute_dict[event].iteritems():
			print "\t\t\t", k, "|",
			if len(v) > 0 and isinstance(v[0], int):
				try:
					avg = float(sum(v))/len(v)
					stdev = robustnetLib.stdevValue(v, avg)
					print "average:", avg, "stdev:", stdev
					continue
				except:
					pass
			
			counter = Counter(v).most_common(3)
			for items in counter:
				print items[0], ":", items[1], "|",
			print
			
			

	def merge_dicts(self, l, name, transition_file):
		DEVELOP = False
		if DEVELOP:
			result = []
			for item in l:
				for i in range(len(item.between)):
					if i >= len(result):
						result.append({})
					val = item.between[i][0]
					if val not in result[i]:
						result[i][val] = 1
					else:
						result[i][val] += 1
		
			for item in result:
				sorted_result = sorted(item.iteritems(), key=operator.itemgetter(1), reverse=True)
				for k, v in sorted_result:
					print k + ":", v,
				print
		time_to_reach_first = self.__create_dict(True)
		duplicates_first = self.__create_dict(True)
		attributes_first = self.__create_dict(False, d=True)
		
		time_to_reach_last= self.__create_dict(True)
		duplicates_last = self.__create_dict(True)
		attributes_last = self.__create_dict(False, d=True)
		inter_time = []
	
		for item in l:
			for k, v in item.time_to_reach_first.iteritems():
				time_to_reach_first[k].append(v)
			for k, v in item.duplicates_first.iteritems():
				duplicates_first[k].append(v)
			for k, v in item.time_to_reach_last.iteritems():
				time_to_reach_last[k].append(v)
			for k, v in item.duplicates_last.iteritems():
				duplicates_last[k].append(v)
			for k, v in item.attributes_first.iteritems():
				self.__merge_attributes(v, attributes_first, k)
			for k, v in item.attributes_last.iteritems():
				self.__merge_attributes(v, attributes_last, k)
			if item.end_time != 0:
				inter_time.append(item.end_time - item.begin_time)
			
		print >>transition_file, name
		print >>transition_file, robustnetLib.listToStr(inter_time, DEL = "\n")
		print name
		print "average:", robustnetLib.meanValue(inter_time), "stdev:", robustnetLib.stdevValue(inter_time)
		print "min-ish:", robustnetLib.quartileResult(inter_time)[0]
		print "min:", min(inter_time)
		for k in time_to_reach_first.keys():
			if max(duplicates_first[k]) == 0 and max(duplicates_last[k]) == 0:
				continue
			print "\t", k, robustnetLib.meanValue(time_to_reach_first[k]), robustnetLib.meanValue(duplicates_first[k]), min(duplicates_first[k]), len(duplicates_first[k])
			self.__print_attributes(attributes_first, k)
			print "\t\t", robustnetLib.meanValue(time_to_reach_last[k]), robustnetLib.meanValue(duplicates_last[k]), min(duplicates_last[k])
			self.__print_attributes(attributes_last, k)

f = open(sys.argv[1])

in_relevant_section = False
event_parser = Event()

#########################################################################
#	Parse file, extract important info				#
#########################################################################

for line in f:
	line = line.strip()
	if len(line) != 0 and  line[0] == "%":
		continue

#	if line.startswith("2013"):
#		in_relevant_section = True
	if len(line) == 0:
		in_relevant_section = not in_relevant_section
		continue
	if in_relevant_section:
		event_parser.addNewLine(line)

if len(sys.argv) > 2:
	event_parser.addUpperLayerPackets(sys.argv[2])

transition_file = None
if len(sys.argv) > 3:
	transition_file = open(sys.argv[3] + "_intervals.txt", "w")

#########################################################################
#	Put in order							#
#########################################################################
all_keys = Event.all_events.keys()
all_keys = sorted(all_keys)
last_key = -1
last_before_state = None
last_after_state = None
sorted_events = []
for k in all_keys:
	actual_time = 0	
#	if last_key != -1:
#		actual_time = k - last_key
	
			
	for event in Event.all_events[k]:
		#if not event.event.startswith("EVENT_LTE") and not event.event.startswith("PACKET") and not event.event.startswith("EVENT_RRC"):
#			continue
		#event.time = actual_time
		if event.before_state != None:
			last_before_state = event.before_state
		else:
			event.before_state = last_before_state
			
		if event.after_state != None:
			last_after_state = event.after_state
		else:
			event.after_state = last_after_state

		event.printme()
		sorted_events.append(event)
		actual_time = 0

	last_key = k


#########################################################################
#	Process, generate statistics					#
#########################################################################

#for event in all_events:
transition = Transition("None", 0)
transition_dict = {}
for event in sorted_events:
	if not transition.update(event):
		# finished updating, go to next one
		transition.find_stats_and_finalize(event)
		# save if valid
		if transition.transition != None and transition.after_transition != None:
			name = transition.transition + " " + transition.after_transition
			if name in transition_dict:
				transition_dict[name].append(transition)
			else:
				transition_dict[name] = [transition]
		transition = Transition(event.after_state, event.time)

for k, v in transition_dict.iteritems():
	v[0].merge_dicts(v, k, transition_file)


