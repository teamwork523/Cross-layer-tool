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
# Map between log id with log entry
PROTOCOL_ID = int("0x11EB", 16)
RRC_ID = int("0x4125", 16)
EUL_STATS_ID = int("0x4311", 16)
UL_PDU_ID = int("0x413B", 16)   # UL on Link Layer info
DL_PDU_ID = int("0x418B", 16)   # DL on Link Layer info
SIG_ID = int("0x4005", 16)  # Signal information
LOGTYPE_MAP = {PROTOCOL_ID: "Protocol Services Data",
               RRC_ID: "WCDMA RRC States",
               EUL_STATS_ID: "EUL Link Statistics", 
               UL_PDU_ID: "UL PDU information", 
               DL_PDU_ID: "DL PDU information",
               SIG_ID: "Signal Strength related"}

############ RRC State
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

TIMER = { FACH_TO_DCH_ID: 2, \
          PCH_TO_FACH_ID: 0.5}

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

# Retransmission mapping
MAX_ENTRIES_LIST = 200

# RLC DL retransmission
RETX_PERIOD_THRESHOLD = 5
MIN_SN_PERIOD = 20
