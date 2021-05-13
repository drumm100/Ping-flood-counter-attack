from datetime import datetime as dt
import socket
import sys
import struct
import math
import os


# DEFS
ETH_P_ALL = 0x0003
ETH_P_SIZE = 65536
ETH_P_IP = 0x0800
IP_PROTO_ICMP = 1


def bytes_to_mac(bytes_mac):
    return ":".join("{:02x}".format(x) for x in bytes_mac)


def createSocket() -> socket:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        print('Debug: Socket created')
        s.bind('eth0', 0)
        return s

    except OSError as message:
        print('Error: ' + str(message))
        sys.exit(1)


if __name__ == "__main__":
    sock = createSocket()
    socket_name = sock.getsockname()
    mac_addr = socket_name[-1]

    print('MAC addr: + ' + bytes_to_mac(mac_addr))

    while True:
        (packet, addr) = sock.recvfrom(65536)
        eth_length = 14
        eth_header = packet[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        packet_type = eth[2]

        if packet_type == ETH_P_IP:
            print("IP Packet")
            ip_header = packet[eth_length:20 + eth_length]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            print("IP Src: " + s_addr)
            print("IP Dst: " + d_addr)









