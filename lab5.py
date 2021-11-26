import pickle
import random
import urllib
from time import strftime, gmtime
from hashlib import sha256
import time
import socket


PREFIX = '  '
MY_IP = '127.0.0.1'
MY_PORT = 55321
BTC_IP = '104.129.171.121'
BTC_PORT = 8333  # Mainnet
BTC_PEER_ADDRESS = (BTC_IP, BTC_PORT)
START_STRING = 'f9beb4d9'
SU_ID = 4124597
HEADER_SIZE = 24  # 4 + 12 + 4 + 4
COMMAND_SIZE = 12
VERSION = 70015
BLOCK_NUMBER = SU_ID % 700000


def send_message(msg_packet, wait=True):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
        peer_sock.connect(BTC_PEER_ADDRESS)
        peer_sock.settimeout(1.5)
        # total_data = []
        try:
            peer_sock.sendall(msg_packet)
        except Exception as e:
            print('Failed to send message to {} at [{}]: {}'
                  .format(BTC_PEER_ADDRESS, time.time(), str(e)))
        else:
            if wait:
                data = peer_sock.recv(1024)
                print('\n****** Received {} bytes from BTC node {} ******'
                      .format(len(data), BTC_PEER_ADDRESS))
                return data

def checksum(payload):
    return sha256(sha256(payload).digest()).digest()[0:4]


def get_empty_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((MY_IP, 0))
        port = sock.getsockname()[1]
    return port

def build_get_blocks_message():
    version = uint32_t(VERSION)
    hash_count = compactsize_t(5)
    block_header_hashes = b'\0' * 32
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])

def build_message(command, payload):
    return build_message_header(command, payload) + payload

def build_ping_message():
    return uint64_t(random.getrandbits(64))


def build_message_header(command, payload=None):
    if not payload:
        payload = ''.encode()
    magic = bytes.fromhex(START_STRING)
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])


def build_version_message():
    version = int32_t(VERSION)  # Version 70015
    services = uint64_t(0)  # Unnamed - not full node
    timestamp = int64_t(int(time.time()))  # Current UNIX epoch
    addr_recv_services = uint64_t(1)  # Full node
    addr_recv_ip_address = ipv6_from_ipv4(BTC_IP)  # Big endian
    addr_recv_port = int(BTC_PORT).to_bytes(2, byteorder='big', signed=False) #uint16_t(BTC_PORT)
    addr_trans_services = uint64_t(0)  # Identical to services
    addr_trans_ip_address = ipv6_from_ipv4(MY_IP)  # Big endian
    addr_trans_port = int(get_empty_port()).to_bytes(2, byteorder='big', signed=False) #uint16_t(get_empty_port())
    nonce = uint64_t(0)
    user_agent_bytes = compactsize_t(0)  # 0 so no user agent field
    start_height = int32_t(0)
    relay = bool_t(False)

    return b''.join([version, services, timestamp, addr_recv_services,
                     addr_recv_ip_address, addr_recv_port, addr_trans_services,
                     addr_trans_ip_address, addr_trans_port, nonce,
                     user_agent_bytes, start_height, relay])

def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)


def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HEADER_SIZE:]
    command = print_header(msg[:HEADER_SIZE], checksum(payload))
    if payload:
        print_payload_label(command)

    if command == 'version':
        print_version_msg(payload)
    # FIXME print out the payloads of other types of messages, too
    if command == 'sendcmpct':
        print_sendcmpct_message(payload)
    if command == 'ping' or command == 'pong':
        print_ping_pong_message(payload)
    if command == 'addr':
        print_addr_message(payload)
    if command == 'feefilter':
        print_feefilter_message(payload)
    return command

def print_payload_label(command):
    print(PREFIX + '{}'.format(command.upper()))
    print(PREFIX + '-' * 56)

def print_feefilter_message(feerate):
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, feerate.hex(), unmarshal_uint(feerate)))

def print_addr_message(payload):
    ip_count_bytes, ip_addr_count = unmarshal_compactsize(payload)
    i = len(ip_count_bytes)
    epoch_time, services, ip_addr, port = payload[i:i + 4], payload[i + 4:i + 12], \
                                    payload[i + 12:i + 28], payload[i + 28:]
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, ip_count_bytes.hex(), ip_addr_count))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",
                        gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} services: {}'.format(prefix, services.hex(), unmarshal_uint(services)))
    print('{}{:32} host: {}'.format(prefix, ip_addr.hex(), ipv6_to_ipv4(ip_addr)))
    print('{}{:32} port: {}'.format(prefix, port.hex(), unmarshal_uint(port)))

def print_ping_pong_message(nonce):
    """
    Print contents of ping/pong message.
    :param nonce: payload (always nonce)
    :return:
    """
    prefix = PREFIX * 2
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))

def print_sendcmpct_message(msg_bytes):
    announce, version = msg_bytes[:1], msg_bytes[1:]
    prefix = PREFIX * 2
    print('{}{:32} announce: {}'.format(prefix, announce.hex(), bytes(announce) != b'\0'))
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))

def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = PREFIX * 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


def split_message(peer_msg_bytes):
    msg_list = []
    while peer_msg_bytes:
        payload_size = unmarshal_uint(peer_msg_bytes[16:20])
        msg_size = HEADER_SIZE + payload_size
        msg_list.append(peer_msg_bytes[:msg_size])
        # Discard to move onto next message
        peer_msg_bytes = peer_msg_bytes[msg_size:]
    return msg_list



def main():
    version = build_version_message()
    version_bytes = build_message('version', version)
    verack_bytes = build_message('verack', ''.encode())
    ping_bytes = build_message('ping', build_ping_message())
    get_blocks_bytes = build_message('getblocks', build_get_blocks_message())
    msg_bytes = version_bytes + get_blocks_bytes + verack_bytes + ping_bytes
    my_msg_list = split_message(msg_bytes)
    for msg in my_msg_list:
        print_message(msg, 'sending')

    peer_msg_bytes = send_message(msg_bytes)
    peer_msg_list = split_message(peer_msg_bytes)
    for msg in peer_msg_list:
        print_message(msg, 'receive')

    # build_get_blocks_message()
    # version_msg = build_version_message()
    # my_version = build_message('version', version_msg)
    # print_message(my_version, 'sending')
    # peer_msg = send_message(my_version)
    # peer_version, peer_verack = split_message(peer_msg)
    # print_message(peer_version, 'receive')
    #
    # my_verack = build_message_header('verack', ''.encode())
    # print_message(my_verack, 'sending')
    # send_message(my_verack, wait=False)
    # print_message(peer_verack, 'receive')

    # verack = build_message_header('verack')
    # my_verack =
    # print_message(my_verack, 'sending')
    # send_message(my_verack)
    # print_message(peer_verack, 'receive')
    #
    # ping = build_ping_message()
    # my_ping = build_message('ping', ping)
    # print_message(my_ping, 'sending')
    # pong = send_message(my_ping)
    # print_message(pong, 'receive')



if __name__ == '__main__':
    main()