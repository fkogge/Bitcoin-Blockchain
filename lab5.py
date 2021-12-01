import pickle
import random
import urllib
from time import strftime, gmtime
from hashlib import sha256
import datetime
import time
import socket

MAX_BLOCKS = 500
BLOCK_GENESIS = bytes.fromhex('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
PREFIX = '  '
MY_IP = '127.0.0.1'
MY_PORT = 55321
BTC_IP = '99.132.89.133'
''' 
IPs used for testing:

47.40.67.209   
104.129.171.121
'''
BTC_PORT = 8333  # Mainnet
BTC_PEER_ADDRESS = (BTC_IP, BTC_PORT)
START_STRING = 'f9beb4d9'
SU_ID = 4124597
HEADER_SIZE = 24  # 4 + 12 + 4 + 4
COMMAND_SIZE = 12
VERSION = 70015
BLOCK_NUMBER = 1000 # FIXME SU_ID % 700000
GENESIS_BYTES = {'version': 1, 'prev_block_header_hash': b'\0' * 32,
                 'merkle_root_hash': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
                 'time': int(datetime.datetime(2009, 1, 3, 10, 15, 5).timestamp()),
                 'n_bits': 486604799, 'nonce': 2083236893}
GEN_VERSION = 1
GEN_PREV_HASH = b'\0' * 32
GEN_MERK_HASH = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
GEN_TIME = int(datetime.datetime(2009, 1, 3, 10, 15, 5).timestamp())
GEN_N_BITS = 486604799
GEN_NONCE = 2083236893
#MAX_SIZE = int.from_bytes(bytes.fromhex('02000000'), byteorder='big', signed=False)
MAX_SIZE = int(32 * 1.048576e6)  # 32 MiB

#64K




def get_block_header(ver=None, prev_hash=None, merk_hash=None, time=None, n_b=None, non=None, genesis=False):
    """
    Get a block header with the specified fields. By default, they all
    correspond to the genesis block.
    :param v:
    :param p:
    :param m_r:
    :param e_t:
    :param n:
    :param non:
    :return:
    """
    if genesis:
        ver = GENESIS_BYTES['version']
        prev_hash = GENESIS_BYTES['prev_block_header_hash']
        merk_hash = GENESIS_BYTES['merkle_root_hash']
        time = GENESIS_BYTES['time']
        n_b = GENESIS_BYTES['n_bits']
        non = GENESIS_BYTES['nonce']

    version = int32_t(ver)
    prev_block_header_hash = prev_hash
    merkle_root_hash = bytearray.fromhex(merk_hash)
    merkle_root_hash.reverse()  # Little endian
    epoch_time = uint32_t(time)
    n_bits = uint32_t(n_b)
    nonce = uint32_t(non)
    return b''.join([version, prev_block_header_hash, merkle_root_hash, epoch_time, n_bits, nonce])



def send_message(sock: socket.socket, msg_packet: bytes):
    sock.sendall(msg_packet)
    data = sock.recv(MAX_SIZE)
    print('\n****** Received {} bytes from BTC node {} ******'.format(
                 len(msg_packet), BTC_PEER_ADDRESS))
    return data

    # total_data = []
    # while True:
    #     sock.settimeout(0.5)
    #     try:
    #         data = sock.recv(MAX_SIZE)
    #         if data:
    #             total_data.append(data)
    #
    #     except:
    #         received_bytes = b''.join(total_data)
    #         print('\n****** Received {} bytes from BTC node {} ******'.format(
    #             len(received_bytes), BTC_PEER_ADDRESS))
    #         return received_bytes

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_sock:
    #     peer_sock.connect(BTC_PEER_ADDRESS)
    #     peer_sock.settimeout(0.5)
    #     total_data = []
    #     try:
    #         peer_sock.sendall(msg_packet)
    #         while wait:
    #             data = peer_sock.recv(MAX_SIZE)
    #             print('\n****** Received {} bytes from BTC node {} ******'
    #                   .format(len(data), BTC_PEER_ADDRESS))
    #             total_data.append(data)
    #
    #     except Exception as e:
    #         if not total_data:
    #             print('Failed to send message to {} at [{}]: {}'
    #                   .format(BTC_PEER_ADDRESS, time.time(), str(e)))
    #         return b''.join(total_data)
    #     else:
    #         pass

def checksum(payload):
    return hash(payload)[:4]

def hash(payload):
    return sha256(sha256(payload).digest()).digest()

def getdata_message(tx_type, header_hash):
    # Identical to inv
    count = compactsize_t(1)
    entry_type = uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash)
    return count + entry_type + entry_hash


def getblocks_message(header_hash):
    version = uint32_t(VERSION)
    hash_count = compactsize_t(1)
    block_header_hashes = bytes.fromhex(header_hash)#sha256(sha256(bytes.fromhex(header_hash)).digest()).digest()
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])




def build_message(command, payload):
    return message_header(command, payload) + payload

def ping_message():
    return uint64_t(random.getrandbits(64))


def message_header(command, payload=None):
    if not payload:
        payload = ''.encode()
    magic = bytes.fromhex(START_STRING)
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])


def version_message():
    version = int32_t(VERSION)  # Version 70015
    services = uint64_t(0)  # Unnamed - not full node
    timestamp = int64_t(int(time.time()))  # Current UNIX epoch
    addr_recv_services = uint64_t(1)  # Full node
    addr_recv_ip_address = ipv6_from_ipv4(BTC_IP)  # Big endian
    addr_recv_port = int(BTC_PORT).to_bytes(2, byteorder='big', signed=False) #uint16_t(BTC_PORT)
    addr_trans_services = uint64_t(0)  # Identical to services
    addr_trans_ip_address = ipv6_from_ipv4(MY_IP)  # Big endian
    addr_trans_port = int(BTC_PORT).to_bytes(2, byteorder='big', signed=False) #uint16_t(get_empty_port())
    nonce = uint64_t(0)
    user_agent_bytes = compactsize_t(0)  # 0 so no user agent field
    start_height = int32_t(BLOCK_NUMBER)
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

def char32_t(n):
    x = bytearray(int(i) for i in n)
    print(x)
    print(x.hex())
    return n.encode('utf-8')

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

def swap_endian(b: bytes):
    """
    Swap the endianness of the given bytes. If little, swaps to big. If big,
    swaps to little.
    :param b:
    :return:
    """
    swapped = bytearray.fromhex(b.hex())
    swapped.reverse()
    return swapped

def print_message(msg, text=None, height=None):
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
        print(PREFIX + '{}'.format(command.upper()))
        print(PREFIX + '-' * 56)

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
    if command == 'getblocks':
        print_getblocks_message(payload)
    if command == 'inv' or command == 'getdata' or command == 'notfound':
        print_inv_message(payload, height)
    if command == 'block':
        print_block_message(payload)
    return command

def print_block_message(payload):


    # Block header (80 bytes)
    version, prev_block, merkle_root, epoch_time, bits, nonce = \
        payload[:4], payload[4:36], payload[36:68], payload[68:72], payload[72:76], payload[76:80]


    txn_count_bytes, txn_count = unmarshal_compactsize(payload)
    txns = payload[80 + len(txn_count_bytes):]

    prefix = PREFIX * 2
    block_hash = swap_endian(hash(payload[:80]))
    print('{}{:32}\n{}{:32} block hash\n'.format(prefix, block_hash.hex()[:32], prefix, block_hash.hex()[32:]))
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_int(version)))
    prev_hash = swap_endian(prev_block)
    print('\n{}{:32}\n{}{:32} prev block hash'.format(prefix, prev_hash.hex()[:32], prefix, prev_hash.hex()[32:]))
    merkle_hash = swap_endian(merkle_root)
    print('\n{}{:32}\n{}{:32} merkle root hash'.format(prefix, merkle_hash.hex()[:32], prefix, merkle_hash.hex()[32:]))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('\n{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} bits: {}'.format(prefix, bits.hex(), unmarshal_uint(bits)))
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))
    print('{}{:32} transaction count: {}'.format(prefix, txn_count_bytes.hex(), txn_count))
    for _ in range(txn_count):
        print('{}{:32} txn: {}'.format(prefix, bits.hex(), unmarshal_uint(bits)))

def print_inv_message(payload, height):
    count_bytes, count = unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i + 4], payload[i + 4:i + 36]
        inventory.append(inv_entry)
        i += 36

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory, start=height if height else 1):
        print('\n{}{:32} type: {}'.format(prefix, tx_type.hex(), unmarshal_uint(tx_type)))
        block_hash = swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} block #{} hash'.format(prefix, block_hash[:32], prefix, block_hash[32:], i))

def print_getblocks_message(payload):
    version = payload[:4]
    hash_count_bytes, hash_count = unmarshal_compactsize(payload[4:])
    i = 4 + len(hash_count_bytes)
    block_header_hashes = []
    for _ in range(hash_count):
        block_header_hashes.append(payload[i:i + 32])
        i += 32
    stop_hash = payload[i:]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))
    print('{}{:32} hash count: {}'.format(prefix, hash_count_bytes.hex(), hash_count))
    for hash in block_header_hashes:
        hash_hex = hash.hex()
        print('\n{}{:32}\n{}{:32} block header hash # {}: {}'.format(prefix, hash_hex[:32], prefix, hash_hex[32:], 1, unmarshal_uint(hash)))
    stop_hash_hex = stop_hash.hex()
    print('\n{}{:32}\n{}{:32} stop hash: {}'.format(prefix, stop_hash_hex[:32], prefix, stop_hash_hex[32:], unmarshal_uint(stop_hash)))

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

def get_last_header(block_bytes):
    return block_bytes[len(block_bytes) - 32:]

def update_current_height(block_list, curr_height):
    return curr_height + (len(block_list[-1]) - 27) // 36

def exchange_messages(bytes_to_send, sock, expected_bytes=None, height=None):
    print_message(bytes_to_send, 'send')
    #bytes_received = send_message(sock, bytes_to_send)

    sock.settimeout(0.5)
    try:
        sock.sendall(bytes_to_send)
        bytes_received = b''
        if expected_bytes:
            while len(bytes_received) < expected_bytes:
                bytes_received += sock.recv(MAX_SIZE)
        else:
            bytes_received = sock.recv(MAX_SIZE)
    except Exception as e:
        print('Failed to send message to {} at [{}]: {}'.format(BTC_PEER_ADDRESS, time.time(), str(e)))
    else:
        print('\n****** Received {} bytes from BTC node {} ******'.format(
            len(bytes_received), BTC_PEER_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list

def send_getblocks_message(input_hash, btc_sock, current_height):
    header_hash = hash(get_block_header(input_hash))
    getblocks_bytes = build_message('getblocks', getblocks_message(header_hash.hex()))
    peer_inv = exchange_messages(getblocks_bytes, btc_sock, 18027, current_height + 1)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in
                        range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, 0)
    return last_500_headers, current_height

def main():
    # gen_header = get_block_header(genesis=True)
    # get_blocks = getblocks_message(gen_header.hex())
    # print(gen_header.hex())
    # print(hash(gen_header).hex())

    btc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    btc_sock.connect(BTC_PEER_ADDRESS)

    # Send version -> receive version, verack
    version_bytes = build_message('version', version_message())
    exchange_messages(version_bytes, btc_sock, 126)

    # Send verack -> receive sendheaders, sendcmpct, ping, addr, feefilter
    verack_bytes = build_message('verack', ''.encode())
    exchange_messages(verack_bytes, btc_sock, 202)


    # # Send ping -> receive pong
    ping_bytes = build_message('ping', ping_message())
    exchange_messages(ping_bytes, btc_sock, 32)

    last_500_headers = []

    # # Send getblocks (after genesis block) -> receive inv
    #genesis_header_hash = hash(get_block_header(genesis=True))
    genesis_header_hash = swap_endian(BLOCK_GENESIS)
    getblocks_bytes = build_message('getblocks', getblocks_message(genesis_header_hash.hex()))
    peer_inv = exchange_messages(getblocks_bytes, btc_sock, 18027, 0)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in
                        range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, 0)

    # Send getblocks until we reach BLOCK_NUMBER -> receive inv
    peer_inv_bytes = b''.join(peer_inv)
    while current_height < BLOCK_NUMBER:
        print(current_height)
        header_hash = get_last_header(peer_inv_bytes)
        getblocks_bytes = build_message('getblocks', getblocks_message(header_hash.hex()))
        peer_inv = exchange_messages(getblocks_bytes, btc_sock, 18027, current_height + 1)
        peer_inv_bytes = b''.join(peer_inv)
        last_500_headers = [peer_inv_bytes[i:i + 32] for i in range(31, len(peer_inv_bytes), 36)]
        current_height = update_current_height(peer_inv, current_height)

    # Retrieve block number, send getdata for the block -> receive merkle block
    my_block_header = last_500_headers[(BLOCK_NUMBER - 1) % 500]
    getdata_bytes = build_message('getdata', getdata_message(2, my_block_header.hex()))
    exchange_messages(getdata_bytes, btc_sock)


    print(my_block_header.hex())
    btc_sock.close()

    # ping_bytes = build_message('ping', build_ping_message())
    # btc_sock.sendall(ping_bytes)
    # pong_resp = btc_sock.recv(MAX_SIZE)
    # print_message(pong_resp, 'receive')

    # gen_header = get_genesis_block_header()
    # print(gen_header.hex())
    # gen_header_hash = sha256(sha256(gen_header).digest()).digest()
    # print(gen_header_hash.hex())

    curr_height = 0
    # version = build_version_message()
    # version_bytes = build_message('version', version)
    # verack_bytes = build_message('verack', ''.encode())
    # ping_bytes = build_message('ping', build_ping_message())
    # genesis_header = get_block_header()
    # get_blocks_bytes = build_message('getblocks', build_get_blocks_message(get_hash(genesis_header).hex()))
    # get_headers_bytes = build_message('getheaders', ''.encode())
    # get_data_bytes = build_message('getdata', build_getdata_message())
    # msg_bytes = version_bytes + verack_bytes + ping_bytes + get_blocks_bytes
    # my_msg_list = split_message(msg_bytes)
    # peer_msg_list = []
    # for msg in my_msg_list:
    #     peer_msg_list.append(send_message(msg))
    #     print_message(msg, 'sending')
    #
    # peer_msg_bytes = b''.join(peer_msg_list)
    # #peer_msg_bytes = send_message(msg_bytes)
    # peer_msg_list = split_message(peer_msg_bytes)
    # for msg in peer_msg_list:
    #     print_message(msg, 'receive')
    #block_bytes_received = (len(peer_msg_list[-1]) - 27) // 36
    #print(block_bytes_received)
    #curr_height = update_current_height(peer_msg_list, curr_height)

    # while curr_height < BLOCK_NUMBER:
    #     last_header = get_last_header(peer_msg_list[-1])
    #     #print(last_header.hex())
    #     get_blocks_bytes_2 = build_message('getblocks', build_get_blocks_message(last_header.hex()))
    #     msg_bytes_2 = version_bytes + verack_bytes + get_blocks_bytes_2
    #     msg_list = split_message(msg_bytes_2)
    #     for m in msg_list:
    #         print_message(m, 'sending')
    #
    #     response = send_message(msg_bytes_2)
    #     response = split_message(response)
    #     for msg in response:
    #         print_message(msg, 'receive')
    #     curr_height = update_current_height(peer_msg_list, curr_height)
    #     print('Local blockchain -> current height: {}'.format(curr_height))




    # m = send_message(version_bytes + verack_bytes + ping_bytes + get_blocks_bytes + get_data_bytes)
    # m = split_message(m)
    # for msg in m:
    #     print_message(msg, 'receive')

    # build_get_blocks_message()
    # version_msg = build_version_message()
    # my_version = build_message('version', version_msg)
    # print_message(my_version, 'sending')
    # peer_msg = send_message(my_version)
    # peer_version, peer_verack = split_message(peer_msg)
    # print_message(peer_version, 'receive')
    #
    # # my_verack = build_message_header('verack', ''.encode())
    # # print_message(my_verack, 'sending')
    # # send_message(my_verack, wait=False)
    # # print_message(peer_verack, 'receive')

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