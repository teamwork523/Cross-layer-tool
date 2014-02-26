#!/usr/bin/env python

"""
@Author Haokun Luo
@Date   02/11/2014

Copyright (c) 2012-2014 RobustNet Research Group, University of Michigan.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by the RobustNet Research Group, University of Michigan.  The name of the
RobustNet Research Group, University of Michigan may not 
be used to endorse or promote products derived
from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

QoE event trace generated by controller app
"""

import sys
import const
import Util as util

class QoE(object):
    """
    Components (also the input content):
    1. timestamp: event timestamp
    2. Action: user action
    3. Event: specific event
    4. Flag: Start/End Flag
    """
    class Event(object):
        def __init__(self, dataList):
            self.timestamp = self.convertTS(dataList[0])
            self.action = dataList[1]
            self.event = dataList[2]
            if len(dataList) > 3:
                self.flag = dataList[3]
            else:
                self.flag = None

        def convertTS(self, ts):
            # Assume input timestamp is 13 digit, upto ms
            return float(ts[:10]) + float(ts[10:]) / 1000.0

        def __str__(self):
            # return all the variables as dict
            return str(vars(self))
            
    # grep the input from a file
    def __init__(self, inFile):
        # Action based map: {"action": [[event_chain_1], [event_chain_2]]}
        self.actionMap = {}

        # Loading the QoE file
        try:
            with open(inFile, "r") as f:
                privAction = None
                while True:
                    line = f.readline()
                    if not line: break
                    data = line.strip().split()
                    newEvent = self.Event(data)
                    if privAction == None:
                        self.actionMap[newEvent.action] = [[]]
                    elif privAction != newEvent.action:
                        if newEvent.action not in self.actionMap:
                            self.actionMap[newEvent.action] = [[]]
                        else:
                            self.actionMap[newEvent.action].append([])
                    self.actionMap[newEvent.action][-1].append(newEvent)
                    privAction = newEvent.action

        except IOError:
            print >> sys.stderr, "ERROR: fail to open " + inFile
            sys.exit(1)

    # network event map with S/F flag
    # Format:
    # startTS -> [endTS, startEvent, endEvent, indexInMap]
    def getNetworkEventMap(self, offset=0):
        if len(self.actionMap) == 0:
            print >> sys.stderr, "ERROR: no active map exist"
            sys.exit(1)

        netEventMap = {}
        privStartEvent = None
        for action in self.actionMap:
            for i in range(len(self.actionMap[action])):
                eventChain = self.actionMap[action][i]
                for event in eventChain:
                    if event.flag != None:
                        if event.flag == "S":
                            privStartEvent = event
                        elif event.flag == "F":
                            if privStartEvent != None and \
                               event.action == privStartEvent.action:
                                netEventMap[privStartEvent.timestamp - offset] = [event.timestamp + offset, \
                                                                                  privStartEvent, \
                                                                                  event, i]
                                # reset previous event
                                privStartEvent = None
        return netEventMap

    # Get the action timer map 
    # Format:
    # startTS -> [endTS, startEvent, endEvent, indexInMap]
    def getActionTimerMap(self, offset=0):
        if len(self.actionMap) == 0:
            print >> sys.stderr, "ERROR: no active map exist"
            sys.exit(1)

        actionTimerMap = {}
        for action in self.actionMap:
            for i in range(len(self.actionMap[action])):
                eventChain = self.actionMap[action][i]
                if len(eventChain) >= 2:
                    actionTimerMap[eventChain[0].timestamp - offset] = [eventChain[-1].timestamp + offset, \
                                                                        eventChain[0], \
                                                                        eventChain[-1], i]
        return actionTimerMap
