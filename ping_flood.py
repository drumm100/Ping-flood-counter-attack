import math
import socket
import struct
import sys
from datetime import datetime as dt

# DEFS
ETH_P_ALL = 0x0003
ETH_P_SIZE = 65536
ETH_P_IP = 0x0800
IP_PROTO_ICMP = 1

KNOWN_HOSTS = dict({})
ATTACK_TIME_SECONDS = 5
ATTACK_PACKET_COUNT_THRESHOLD = 10
ATTACK_PACKET_INTERVAL_THRESHOLD = 0.01


def bytes_to_mac(bytes_mac):
    return ":".join("{:02x}".format(x) for x in bytes_mac)


def addHost(ip: str, mac: str = ''):
    if ip not in KNOWN_HOSTS.keys():
        print('--- Add founded Ip ---')
        print('-> Ip: ', ip)
        print('-> MAC: ', mac)
        print('-> Math.inf', math.inf)

        KNOWN_HOSTS[ip] = dict({
            'packageInterval': math.inf,
            'packageCount': 0,
            'MAC': mac,
        })

        print('--> MAC:', bytes_to_mac(eth[1]))
        print('--> IP:', source_address)
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


def verifyPacket(ip: str):
    now = dt.now()

    if 'lastPacketAt' not in KNOWN_HOSTS[ip].keys():
        KNOWN_HOSTS[ip]['lastPacketAt'] = now
        return

    packet_inteval = now - KNOWN_HOSTS[ip]['lastPacketAt']
    KNOWN_HOSTS[ip]['packageInterval'] = packet_inteval.total_seconds()
    KNOWN_HOSTS[ip]['lastPacketAt'] = now


def getPacketInterval(ip: str):
    if 'packageInterval' not in KNOWN_HOSTS[ip].keys():
        KNOWN_HOSTS[ip]['packageInterval'] = math.inf
    return KNOWN_HOSTS[ip]['packageInterval']


def isPingFloodAttack(ip: str, time_interval: float):
    if 'packageCount' not in KNOWN_HOSTS[ip].keys():
        KNOWN_HOSTS[ip]['packageCount'] = 0
        return False

    if time_interval < ATTACK_PACKET_INTERVAL_THRESHOLD:
        KNOWN_HOSTS[ip]['packageCount'] += 1

    if KNOWN_HOSTS[ip]['packageCount'] >= ATTACK_PACKET_COUNT_THRESHOLD:
        return True

    return False


def debugPrint():
    for ip in KNOWN_HOSTS.keys():
        packet_interval = 0
        last_packet_at = 0
        packet_count = 0
        mac = ''

        if 'packageInterval' in KNOWN_HOSTS[ip].keys():
            packet_interval = KNOWN_HOSTS[ip]['packageInterval']
        if 'lastPacketAt' in KNOWN_HOSTS[ip].keys():
            last_packet_at = KNOWN_HOSTS[ip]['lastPacketAt']
        if 'packageCount' in KNOWN_HOSTS[ip].keys():
            packet_count = KNOWN_HOSTS[ip]['packageCount']
        if 'MAC' in KNOWN_HOSTS[ip].keys():
            mac = KNOWN_HOSTS[ip]['MAC']

        print('#################')
        print('- IP Address: ', ip,
              '\t- MAC Address: ', mac,
              '\t- Packet Interval: ', packet_interval,
              '\t- Last packet at: ', last_packet_at,
              '\t- Packet counts: ', packet_count)
        print('#################')


# ------------------------ Flooding ------------------------

def getHostsList(ip_attack: str):
    hosts = []

    for ip in KNOWN_HOSTS.keys():
        if ip == ip_attack:
            continue
        item = dict({
            'ip_dest': ip,
            'mac_dest': KNOWN_HOSTS[ip]['MAC'],
        })
        hosts.append(item)

    return hosts


def pingFloodCounterAttack(ip_attack: str, max_time: int):
    print(' ------ Start flooding ------ ')

    start_time = dt.now()
    info_time = dt.now()
    hosts_list = getHostsList(ip_attack)
    status = [0 for _ in range(len(hosts_list))]

    while True:
        exec_elapsed_sec = (dt.now() - start_time).total_seconds()
        info_elapsed = (dt.now() - info_time).total_seconds()

        if info_elapsed >= 1:
            info_time = dt.now()

        if exec_elapsed_sec >= max_time:
            break

        for i in range(len(hosts_list)):
            bot = hosts_list[i]
            s = getSocket(None, socket.getprotobyname('icmp'))
            sendPing(s, ip_attack, bot['ip_dest'])
            s.close()
            status[i] += 1

    print('Host list:', hosts_list)
    print('Status:', status)
    print(' ------ End flooding ------ ')


# ------------------------ Flooding ------------------------

# ------------------------ Send Ping ------------------------

def getChecksum(msg: bytes):
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


def getIcmpPacket():
    icmp_header_props = getIcmpRequestHeader()
    icmp_header = struct.pack(
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
    checksum = getChecksum(icmp_header + data)
    icmp_header = struct.pack(
        '!BBHHH',
        icmp_header_props['type'],
        icmp_header_props['code'],
        checksum,
        icmp_header_props['id'],
        icmp_header_props['seqnumber'],
    )
    icmp_packet = icmp_header + data
    return icmp_packet


def getIPPacket(ip_source: str, ip_dest: str):
    # Header IP
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


def getSocket(if_net: str, proto: int = socket.ntohs(ETH_P_ALL)):
    try:
        s = None
        if proto == socket.getprotobyname('icmp'):
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              proto)
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              proto)
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

                print("ICMP Type: ", icmp_type)
                print("ICMP Code: ", icmp_code)

                if icmp_type == 8 and icmp_code == 0 :
                    print("Echo Request")

                    addHost(source_address, bytes_to_mac(eth[1]))
                    verifyPacket(source_address)
                    packet_interval = getPacketInterval(source_address)

                    if isPingFloodAttack(source_address, packet_interval):
                        debugPrint()
                        pingFloodCounterAttack(source_address, ATTACK_TIME_SECONDS)

                #if icmp_type == 0 and icmp_code == 0 :
                    #print("Echo Reply")










