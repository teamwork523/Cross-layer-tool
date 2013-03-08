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
ETHERNET_HEADER = 14

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

# map between RRC id and RRC state
FACH_ID = 2
DCH_ID = 3
PCH_ID = 4
RRC_MAP = {FACH_ID: "CELL_FACH",
           DCH_ID: "CELL_DCH",
           PCH_ID: "CELL_PCH"}

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

# RLC DL retransmission
RETX_PERIOD_THRESHOLD = 5
MIN_SN_PERIOD = 20
