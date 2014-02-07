#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/03/2014

Parser for logcat file
"""

import os, sys, time
from datetime import datetime, date
import calendar
import const
import Util as util

PARSE_DEBUG = False

class logcatParser(object):
    # extract each line's information
    class logcatEntry(object):
        def __init__(self, line):
            splited_line = line.split()
            self.timestamp = self.convertToTimestamp(splited_line[0], splited_line[1])
            # assume pid and tid exist
            self.pid = (int)(splited_line[2])
            self.tid = (int)(splited_line[3])
            self.priority = splited_line[4]
            self.keyword = splited_line[5]
            if self.keyword[-1] == ":":
                self.content = " ".join(splited_line[6:])
                self.keyword = self.keyword[:-1]
            else:
                self.content = " ".join(splited_line[7:])
            # looking for stall message
            self.stall_msg = None
            self.parseForVideoStall()
            # looking for buffering message
            self.buffering = None
            if const.MEDIA_PLAYER_BUFFERING in self.content:
                self.buffering = (int)(splited_line[-1])
            

        # convert to linux timestamp
        def convertToTimestamp(self, month_date, hr_min_sec_minSec, year=date.today().year):
            splited_month_date = month_date.split("-")
            month = (int)(splited_month_date[0])
            day = (int)(splited_month_date[1])
            [secsList, millisec] = hr_min_sec_minSec.split('.')
            [hour, minutes, sec] = secsList.split(':')
            dt = datetime(year, month, day, (int)(hour), (int)(minutes), (int)(sec))
            unixTime = calendar.timegm(dt.utctimetuple())
            return unixTime + float(millisec) / 1000.0

        ###################################
        ############ Media Player #########
        ###################################
        # find the media related information
        def parseForVideoStall(self):
            if const.MEDIA_PLAYER_WARNING_TAG in self.content:
                if str(const.MEDIA_PLAYER_STALL_START) in self.content:
                    self.stall_msg = const.MEDIA_PLAYER_STALL_START
                elif str(const.MEDIA_PLAYER_STALL_END) in self.content:
                    self.stall_msg = const.MEDIA_PLAYER_STALL_END
                elif str(const.MEDIA_PLAYER_STALL_BANDWIDTH_LOW) in self.content:
                    self.stall_msg = const.MEDIA_PLAYER_STALL_BANDWIDTH_LOW

        # print the current content for debug purpose
        def debug(self):
            DEL = "\t"
            print "ts: " + str(self.timestamp) + DEL + \
                  "pid: " + str(self.pid) + DEL + \
                  "tid: " + str(self.tid) + DEL + \
                  "priority: " + str(self.priority) + DEL + \
                  "keyword: " + str(self.keyword) + DEL + \
                  "Stall: " + str(self.stall_msg) + DEL + \
                  "Buffer: " + str(self.buffering)

    # logcat parser
    def __init__(self, inFile, keywords=[]):
        # include the keywords
        self.keywords = keywords
        # map from keyword to a list of 
        self.logMap = {}

        if len(inFile) == 0:
            print >> sys.stderr, "ERROR: Empty Logcat filepath!!!"

        logcatFile = open(inFile, "r")
        # require special synchronization message in the log to figure out
        # the time difference (logtime + diff = actual time)
        self.timediff = None

        while True:
            line = logcatFile.readline()
            if not line: break
            if self.checkWhetherKeywordExistsinLine(line):
                curLog = self.logcatEntry(line)
                if curLog.keyword not in self.logMap:
                    self.logMap[curLog.keyword] = []
                self.logMap[curLog.keyword].append(curLog)
                if PARSE_DEBUG:
                    curLog.debug()
                # looking for a log difference
                if const.TIME_SYC_TAG in curLog.content:
                    splitted_line = line.split()
                    realtime = ((int)(splitted_line[-1])) / 1000.0
                    self.timediff = realtime - curLog.timestamp
                    if PARSE_DEBUG:
                        print "Time difference is " + str(self.timediff)
        
        # update the timestamp in the log entries
        self.updateTimeStamp()

        logcatFile.close()
    
    # get the buffer map (ts -> bufferValue)
    def getBufferMap(self):
        bufferMap = {}
        for log in self.logMap[const.MEDIA_PLAYER_TAG]:
            if log.buffering != None:
                bufferMap[log.timestamp] = log.buffering
        return bufferMap

    # get the stall period {start_time:end_time}
    def getStallPeriodMap(self):
        stallMap = {}
        privStallStart = None
        for log in self.logMap[const.MEDIA_PLAYER_TAG]:
            if log.stall_msg == const.MEDIA_PLAYER_STALL_START:
                privStallStart = log
            elif log.stall_msg == const.MEDIA_PLAYER_STALL_END:
                stallMap[privStallStart.timestamp] = log.timestamp
        return stallMap

    # update all the log's timestamp
    def updateTimeStamp(self):
        if self.timediff != None:
            for key in self.logMap:
                for log in self.logMap[key]:
                    log.timestamp += self.timediff

    # check whether a line contain a keyword
    def checkWhetherKeywordExistsinLine(self, line):
        for kw in self.keywords:
            if kw in line:
                return True
        return False
