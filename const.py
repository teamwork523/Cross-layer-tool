
# Map month to numerical value
MONTH_MAP = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, \
             "may": 5, "jun": 6, "jul": 7, "aug": 8, \
             "sep": 9, "oct": 10, "nov": 11, "dec": 12}

# Map between log id with log entry
PROTOCOL_ID = "0x11EB"
RRC_ID = "0x4125"
LOGTYPE_MAP = {PROTOCOL_ID: "Protocol Services Data",
               RRC_ID: "WCDMA RRC States"}

# map between RRC id and RRC state
FACH_ID = 2
DCH_ID = 3
PCH_ID = 4
RRC_MAP = {FACH_ID: "CELL_FACH",
           DCH_ID: "CELL_DCH",
           PCH_ID: "CELL_PCH"}
