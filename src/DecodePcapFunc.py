#!/usr/bin/env python

import struct
import socket
import json
import sys
import const

def decode_PcapFileHeader(B_datastring):
 
    """   
        4 bytes       2 bytes     2 bytes     4 bytes    4 bytes   4 bytes   4 bytes
        ------------------------------------------------------------------------------
Header  | magic_num | ver_major | ver_minor | thiszone | sigfigs | snaplen | linktype|
        ------------------------------------------------------------------------------
    """
    header = {}
    header['magic_number'] = B_datastring[0:4]
    header['version_major'] = B_datastring[4:6]
    header['version_minor'] = B_datastring[6:8]
    header['thiszone'] = B_datastring[8:12]
    header['sigfigs'] = B_datastring[12:16]
    header['snaplen'] = B_datastring[16:20]
    header['linktype'] = struct.unpack("I", B_datastring[20:24])[0]
    return header
 
 
def decode_PcapDataPcaket(B_datastring):
    """   
          4 bytes    4 bytes    4 bytes 4 bytes   
        ----------------------------------------------
Packet  | GMTtime | MicroTime | CapLen | Len |  Data |
        ----------------------------------------------
        |------------Packet Header-----------|
    """
    packet_num = 0
    packet_data = []
    header = ''
    #header = {}
    data = ''
    # Ignore the global header
    i = 24

    while(i+16<len(B_datastring)):
        
       #header['GMTtime'] = B_datastring[i:i+4]
       #header['MicroTime'] = B_datastring[i+4:i+8]
       #header['CapLen'] = B_datastring[i+8:i+12]
       #header['Len'] = B_datastring[i+12:i+16]
        
       # the len of this packet
       header = B_datastring[i:i+16]
       packet_len = struct.unpack('I', B_datastring[i+8:i+12])[0]
       #print struct.unpack('I', B_datastring[i+8:i+12])
       #print("Len: ", packet_len)

       # the data of this packet
       data = B_datastring[i+16:i+16+packet_len]
      
       # save this packet data
       packet_data.append((header,data))
 
       i = i + packet_len + 16
       packet_num += 1
    return packet_data

def read_Pcap(fileName):
    filepcap = open(fileName,'rb')
    string_data = filepcap.read()
    packet_data = decode_PcapDataPcaket(string_data)
    global_header = decode_PcapFileHeader(string_data[:24])
    # return both header and data
    return (global_header, packet_data)

def read_json_rssi(fileName):
    filepcap = open(fileName,'rb')
    string_data = filepcap.read().decode(encoding='utf-8', errors='strict')
    json_data = json.loads(string_data)
    filepcap.close()
    return json_data[1]

def packet_time(packet_data, i):
    seconds = struct.unpack('I',packet_data[i][0][0:4])[0]
    microseconds = struct.unpack('I',packet_data[i][0][4:8])[0]
    return (seconds * 1000 + microseconds/1000)/1000.0

def interval(time1, time2):
    seconds = struct.unpack('I',time2[0:4])[0] - struct.unpack('I',time1[0:4])[0]
    microseconds = struct.unpack('I',time2[4:8])[0] - struct.unpack('I',time1[4:8])[0]
    return (seconds + microseconds/1000000)

##################################################################
####################### IP Fields ################################
##################################################################
def dst_ip(packet_data, i, link_len):
	base = link_len + 16
	return get_ip(packet_data, i, base)
	
def src_ip(packet_data, i, link_len):
	base = link_len + 12
	return get_ip(packet_data, i, base)

def get_ip(packet_data, i, base):
	return str(ord(packet_data[i][1][base:base+1])) + "." + \
		   str(ord(packet_data[i][1][base+1:base+2])) + "." + \
		   str(ord(packet_data[i][1][base+2:base+3])) + "." + \
		   str(ord(packet_data[i][1][base+3:base+4]))

##################################################################
###################### TCP Fields ################################
##################################################################

def dst_port(packet_data, i, link_len):
	base = link_len + 20
	return get_port(packet_data, i, base)
	
def src_port(packet_data, i, link_len):
	base = link_len + 22
	return get_port(packet_data, i, base)

def get_port(packet_data, i, base):
	return ord(packet_data[i][1][base:base+1]) * 256 + \
		   ord(packet_data[i][1][base+1:base+2])

def window_size(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len + 36]) * 256 + ord(packet_data[i][1][link_len + 37])

def sequence_num(packet_data, i):
	# (1 << 24), (1 << 16), (1 << 8)
	return ord(packet_data[i][1][40]) * 16777216 + ord(packet_data[i][1][41]) * 65536 + ord(packet_data[i][1][42]) * 256 + ord(packet_data[i][1][43])

def sequence_num(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len+24]) * 16777216 + ord(packet_data[i][1][link_len+25]) * 65536 + ord(packet_data[i][1][link_len+26]) * 256 + ord(packet_data[i][1][link_len+27])

def ack_num(packet_data, i):
	return ord(packet_data[i][1][44]) * 16777216 + ord(packet_data[i][1][45]) * 65536 + ord(packet_data[i][1][46]) * 256 + ord(packet_data[i][1][47])
# transform like '\x01\x0e\0xb0' to '0x010eb0'

def ack_num(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len+28]) * 16777216 + ord(packet_data[i][1][link_len+29]) * 65536 + ord(packet_data[i][1][link_len+30]) * 256 + ord(packet_data[i][1][link_len+31])

def window_size_server(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len + 34]) * 256 + ord(packet_data[i][1][link_len + 35])

def sequence_num_server(packet_data, i):
	return packet_data[i][1][38] * 16777216 + packet_data[i][1][39] * 65536 + packet_data[i][1][40] * 256 + packet_data[i][1][41]

def ack_num_server(packet_data, i):
	return packet_data[i][1][42] * 16777216 + packet_data[i][1][43] * 65536 + packet_data[i][1][44] * 256 + packet_data[i][1][45]

def tcp_flag_bit(packet_data, i, link_len, index):
	flag = tcp_flag(packet_data, i, link_len)
	return not not (flag >> index & 0x1)

def tcp_flag(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len + 32]) * 256 + ord(packet_data[i][1][link_len + 33])
	
def ip_length(packet_data, i, link_len):
	return ord(packet_data[i][1][link_len + 2]) * 256 + ord(packet_data[i][1][link_len + 3])
	
def tcp_header_size(packet_data, i, link_len):
	return (ord(packet_data[i][1][link_len + 32]) >> 4) * 4

def tcp_seg_size(packet_data, i, link_len):
	return ip_length(packet_data, i, link_len) - tcp_header_size(packet_data, i, link_len) - 20

def str_to_hex(strs):
    hex_data =''
    for i in range(len(strs)):
        tem = strs[i]
        tem = hex(tem)
        if len(tem)==3:
            tem = tem.replace('0x','0x0')
        tem = tem.replace('0x','')
        hex_data = hex_data+tem
    return '0x'+hex_data

def ip_equal(ipstr,ipaddr):
    #print (ipstr)
    #print (str_to_hex(ipstr), ':',hex(socket.htonl(struct.unpack("I",socket.inet_aton(ipaddr))[0])))
    return (str_to_hex(ipstr) == hex(socket.htonl(struct.unpack("I",socket.inet_aton(ipaddr))[0])))

def port_equal(portstr, port):
    #print (portstr)
    #print(str_to_hex(portstr), ':',e4dhex(port));
    return (str_to_hex(portstr) == hex(port))

def display_hexdata(frame_data):
    row_num = ['0x0000','0x0010','0x0020','0x0030','0x0050','0x0060','0x0070']
    raw_data = []
    asc_data = []
    display_data = []
    temp = ''
    for i in range(len(frame_data)):
       temp = ord(frame_data[i])
       temp = hex(temp)
       if len(temp)==3:
           temp = temp.replace('0x','0x0')
       temp = temp.replace('0x',' ')
       raw_data.append(temp)
       asc = int(temp,16)
       if(asc>=32 and asc<=126):
           asc_data.append(chr(asc))
       else:
           asc_data.append('.')
    while(len(raw_data)%16!=0):
       raw_data.append('   ')
       asc_data.append(' ')
    temp1 = ''
    temp2 = ''
    rownum = 0
    for j in range(len(raw_data)):
       if (j==0 or j%16!=0):
           temp1 = temp1+raw_data[j]
           temp2 = temp2+asc_data[j]
       elif j%16==0:
           temp1 = row_num[rownum]+temp1+';'+temp2
           rownum=rownum+1
           display_data.append(temp1)
           temp1 = ''
           temp2 = ''
           temp1=temp1+raw_data[j]
           temp2=temp2+asc_data[j]
    temp1 = row_num[rownum]+temp1+';'+temp2
    display_data.append(temp1)
    return display_data

# payload calculation
def payload(packet_data, i, link_len, header_size):
    # adapt to the hex version that QXDM use
    payload = ""
    for byte in packet_data[i][1][link_len + 20 + header_size:]:
        # exclude "\x"
        payload += hex(ord(byte))[2:].upper()
    return payload

# TCP payload
def tcp_payload(packet_data, i, link_len):
    header_len = tcp_header_size(packet_data, i, link_len)
    return payload(packet_data, i, link_len, header_len)

##################################################################
###################### UDP Fields ################################
##################################################################
    """   
               4 bytes    4 bytes      4 bytes  
             ----------------------------------------------
Instrumented | Seq Num | Wait_index | Granularity | 
Packet
             ----------------------------------------------
             |------------ UDP Payload-----------|

    """
# notice: src/dst port locate the same location as TCP, so directly borrow from TCP
def udp_seg_size(packet_data, i, link_len):
    return ip_length(packet_data, i, link_len) - const.UDP_Header_Len - const.IP_Header_Len

# UDP payload
def udp_payload(packet_data, i, link_len):
    return payload(packet_data, i, link_len, 8)

# extract the sequence number if there is one in the data
# Assume the UDP sequence number resides in the first four bytes in the UDP payload
def udp_seq_num(packet_data, i, link_len):
    # assume the first 4 bytes are seq_num
    max_lookup_byte_len = 4
    start_index = link_len + const.IP_Header_Len + const.UDP_Header_Len
    if len(packet_data[i][1]) <= start_index:
        return None
    return struct.unpack(">i", packet_data[i][1][start_index:start_index+max_lookup_byte_len])[0]

# extract the wait_index and granularity from the trace
def udp_gap_period(packet_data, i, link_len):
    # calculate the real gap period from the wait index and granularity
    start_index = link_len + const.IP_Header_Len  + const.UDP_Header_Len + 4
    instr_len_unit = 4
    if len(packet_data[i][1]) <= start_index + instr_len_unit * 2:
        return None
    wait_index = struct.unpack(">i", packet_data[i][1][start_index:start_index+instr_len_unit])[0]
    granularity = struct.unpack(">i", packet_data[i][1][start_index+instr_len_unit:start_index+instr_len_unit*2])[0]
    if wait_index > 0 and wait_index < const.UDP_WAIT_LIMIT and \
       granularity > 0 and granularity < const.UDP_GRAN_LIMIT:
        return wait_index * granularity / 1000.0
    return None

##################################################################

def main():
    # A sample usage for getting UDP payload, 14 is the ethernet header length
    # data is in the format of (wireshark_header, layer2-4_header+payload)
    header, data = read_Pcap(sys.argv[1])
    print len(data)
    for i in range(10):
        # print ip_length(data, i, 14)
        # print tcp_header_size(data, i, 14)
        # print tcp_seg_size(data, i, 14)
        print "%dth payload:" % i
        print udp_payload(data, i, 14)
	
if __name__ == "__main__":
    main()

