# Timestamp accuracy, in terms of milliseconds
TS_DELTA = 1

# Map month to numerical value
MONTH_MAP = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, \
             "may": 5, "jun": 6, "jul": 7, "aug": 8, \
             "sep": 9, "oct": 10, "nov": 11, "dec": 12}

# Map between log id with log entry
PROTOCOL_ID = int("0x11EB", 16)
RRC_ID = int("0x4125", 16)
LOGTYPE_MAP = {PROTOCOL_ID: "Protocol Services Data",
               RRC_ID: "WCDMA RRC States"}

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
