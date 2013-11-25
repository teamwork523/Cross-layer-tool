import math

# Timestamp accuracy, in terms of milliseconds
TS_DELTA = 1

# Map month to numerical value
MONTH_MAP = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, \
             "may": 5, "jun": 6, "jul": 7, "aug": 8, \
             "sep": 9, "oct": 10, "nov": 11, "dec": 12}

############################################################################
################################# PCAP Related #############################
############################################################################
# Link layer header type
LINKTYPE_ETHERNET = 1
LINKTYPE_RLC = 12

# Common byte length
LINK_HEADER_LEN = {LINKTYPE_ETHERNET:14,\
			   	   LINKTYPE_RLC:0}

# Upper bound for throughput
UPPER_BOUND_TP = math.pow(2, 30)

# Number of ACKs that triggers Fast retransmission
FAST_RETX_COUNT = 3

# Retx packet gap based on wireshark's implementation (in secs)
RETX_GAP = 0.003

############################################################################
################################# QCAT Related #############################
############################################################################
# QxDM log of interest summary

# General
PROTOCOL_ID = int("0x11EB", 16)

# WCDMA
RRC_ID = int("0x4125", 16)
EUL_STATS_ID = int("0x4311", 16)
DL_CONFIG_PDU_ID = int("0x4132", 16)
UL_CONFIG_PDU_ID = int("0x4133", 16)    # polling configurations included
DL_CTRL_PDU_ID = int("0x4134", 16)      # LIST/ACK info on UL RLC AM
UL_PDU_ID = int("0x413B", 16)   # UL on Link Layer info
DL_PDU_ID = int("0x418B", 16)   # DL on Link Layer info
SIG_ID = int("0x4005", 16)  # Signal information

# LTE
LTE_UL_RLC_PDU_ID = int("0xB092", 16)
LTE_DL_RLC_PUD_ID = int("0xB082", 16)
LTE_UL_CONFIG_RLC_ID = int("0xB091", 16)
LTE_DL_CONFIG_RLC_ID = int("0xB081", 16)
LTE_CELL_MEASUREMENT_ID = int("0xB180", 16)

# EVENTs
EVENT_ID = int("0x1FFB", 16)

LOGTYPE_MAP = {PROTOCOL_ID: "Protocol Services Data",
               RRC_ID: "WCDMA RRC States",
               EUL_STATS_ID: "EUL Link Statistics", 
               UL_PDU_ID: "UL PDU information", 
               DL_PDU_ID: "DL PDU information",
               SIG_ID: "Signal Strength related",
               DL_CONFIG_PDU_ID: "Downlink RLC configuration",
               UL_CONFIG_PDU_ID: "Uplink RLC configuration",
               DL_CTRL_PDU_ID: "Downlink control PDU"}

####################################
############### UDP ################
####################################
UDP_RTT_LIMIT = 5
# instrumented index value
UDP_WAIT_LIMIT = 32
UDP_GRAN_LIMIT = 1024

# Include data configuration settings
# TODO: hard configured, to be changed
DATA_LOGIC_CHANNEL_ID = 19

####################################
############ RRC State #############
####################################
# map between RRC id and RRC state
FACH_ID = 2
DCH_ID = 3
PCH_ID = 4
FACH_TO_DCH_ID = 5
PCH_TO_FACH_ID = 6
# TODO: Assign the DCH later
# DCH_LATER_ID = 7

RRC_MAP = {FACH_ID: "CELL_FACH", \
           DCH_ID: "CELL_DCH", \
           PCH_ID: "CELL_PCH", \
           FACH_TO_DCH_ID: "PROMOTE_TO_DCH", \
           PCH_TO_FACH_ID: "PROMOTE_TO_FACH"}

# Generic RRC states in UMTS w/o Arteficial RRC State
RRC_ORIG_MAP = {FACH_ID: "CELL_FACH", \
                DCH_ID: "CELL_DCH", \
                PCH_ID: "CELL_PCH"}

# 1 sec for DCH promotion, and 0.2 sections for PCH promotion
TIMER = { FACH_TO_DCH_ID: 1, \
          PCH_TO_FACH_ID: 0.2}

# transport layer protocol map
IP_ID = int("0x01", 16) # QCAT protocol id
TCP_ID = 6
UDP_ID = 17
IDtoTLP_MAP = {TCP_ID: "TCP",
               UDP_ID: "UDP"}
TLPtoID_MAP = {"TCP": TCP_ID,
               "UDP": UDP_ID}
               
# QCAT Entry constant
Payload_Header_Len = 8
IP_Header_Len = 20
TCP_Header_Len = 20 + 12 # include option
UDP_Header_Len = 8

####################################
############### RLC ################
####################################
RLC_LI_THRESHOLD = 126 # If the current PDU size is greater than 126, then LI length is 15 bits (2 bytes including E bit)

# Retransmission mapping (heuristics)
MAX_ENTRIES_LIST = 10000
MIN_MAPPING_THRESHOLD = 0.5

# maximum lookup ahead in search for the polling bit
MAX_LOOK_AHEAD_INDEX = 200

# RLC DL retransmission
RETX_PERIOD_THRESHOLD = 5
MIN_SN_PERIOD = 20

# Maximum RLC UL sequence number
MAX_RLC_UL_SEQ_NUM = 4096


