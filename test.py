import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("====== ethernet header ======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1B1B1H1H2s1B1B2s4s4s", data)

    ip_ver = ip_header[0]//16
    ip_len = ip_header[0]%16
    differ = ip_header[1]//16
    explicit = ip_header[1]%16
    total_len = ip_header[2]
    identifi = ip_header[3]
    flags = ip_header[4].hex()
    time = ip_header[5]
    protocol = ip_header[6]
    header_check = ip_header[7].hex()
    ip_src = convert_ip_address(ip_header[8])
    ip_dst = convert_ip_address(ip_header[9])


    print("====== ip header ======")
    print("ip_version:", ip_ver)
    print("ip_length:", ip_len)
    print("differentiated_service_codepoint:", differ)
    print("explicit_congestion_notification:", explicit)
    print("total_length:", total_len)
    print("identification:", identifi)
    print("flags: 0x"+flags)
    flags = int(flags, 16)
    print(">>>reserved_bit:", flags>>15)
    print(">>>not_fragments:", (flags>>14)%2)
    print(">>>fragments:", (flags>>13)%2)
    print(">>>fragments_offset:", flags%(1<<13))
    print("Time to live:", time)
    print("protocol:", protocol)
    print("header checksum: 0x"+header_check)
    print("source_ip_address:", ip_src)
    print("dest_ip_address:", ip_dst)

def convert_ip_address(data):
    ip_addr=list()
    for i in data:
        ip_addr.append(str(i))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!1H1H1I1I1H1H2s1H", data)
    
    tcp_src = tcp_header[0]
    tcp_dst = tcp_header[1]
    seq_num = tcp_header[2]
    ack_num = tcp_header[3]
    header_len = tcp_header[4]>>12 # 4bit
    Flags = (tcp_header[4]%(1<<12)) # 12bit
    reserve = Flags>>9 # biggest 3
    nonce = (Flags>>8)%2 # from left 4
    cwr = (Flags>>7)%2  #5
    ecn_echo = (Flags>>6)%2 #6
    urgent = (Flags>>5)%2 #7
    ack = (Flags>>4)%2 #8
    push = (Flags>>3)%2#9
    reset = (Flags>>2)%2 #10
    syn = (Flags>>1)%2 #11
    fin = Flags%2 #12
    win_size = tcp_header[5]
    checksum = "0x"+tcp_header[6].hex()
    urg_p = tcp_header[7]

    print("====== tcp header ======")
    print("src_port:", tcp_src)
    print("dec_port:", tcp_dst)
    print("seq_num:", seq_num)
    print("ack_num:", ack_num)
    print("header_len:", header_len)
    print("flags:", Flags)
    print(">>>reserved:", reserve)
    print(">>>nonce:", nonce)
    print(">>>cwr:", cwr)
    print(">>>ecn-echo:", ecn_echo)
    print(">>>urgent:", urgent)
    print(">>>ack:", ack)
    print(">>>push:", push)
    print(">>>reset:", reset)
    print(">>>syn:", syn)
    print(">>>fin:", fin)
    print("window_size_value:", win_size)
    print("checksum:", checksum)
    print("urgent_pointer:", urg_p)

def parsing_udp_header(data):
    udp_header = struct.unpack("!1H1H1H2s",data)
    udp_src = udp_header[0]
    udp_dst = udp_header[1]
    udp_len = udp_header[2]
    udp_checksum = "0x"+udp_header[3].hex()

    print("====== udp header ======")
    print("src_port:", udp_src)
    print("dst_port:", udp_dst)
    print("length:", udp_len)
    print("header checksum:", udp_checksum)


recv_socket=socket.socket(socket.PF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0800))

while True:
    print("<<<<<<Packet Capture Start>>>>>>")
    data = recv_socket.recvfrom(20000)

    print(data[0][23])
    print(data)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data[0][14:34])
    #parsing_tcp_header(data[0][34:54])
    parsing_udp_header(data[0][34:42])
    break
    print("")
