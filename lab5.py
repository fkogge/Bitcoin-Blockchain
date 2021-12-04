import pickle
import random
import urllib
from time import strftime, gmtime
from hashlib import sha256
import datetime
import time
import socket

#BTC_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
MAX_BLOCKS = 500
BLOCK_GENESIS = bytes.fromhex('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
PREFIX = '  '
MY_IP = '127.0.0.1'
MY_PORT = 55321
BTC_IP = '99.132.89.133'
''' 
IPs used for testing:
99.132.89.133
47.40.67.209   
104.129.171.121
'''
BTC_PORT = 8333  # Mainnet
BTC_PEER_ADDRESS = (BTC_IP, BTC_PORT)
START_STRING = 'f9beb4d9'
EMPTY_STRING = ''.encode()
SU_ID = 4124597
HEADER_SIZE = 24  # 4 + 12 + 4 + 4
COMMAND_SIZE = 12
VERSION = 70015
BLOCK_NUMBER = SU_ID % 10000
BLOCK_VALUE = 0
MAX_SIZE = 64000#int(32 * 1.048576e6)  # 32 MiB

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

def checksum(payload: bytes):
    """
    Calculate Bitcoin protocol checksum - first 4 bytes of
    sha256(sha256(payload)).
    :param payload: payload bytes
    :return: checksum
    """
    return hash(payload)[:4]

def hash(payload: bytes):
    """
    Calculate the Bitcoin protocol hash - nested sha256 hash.
    :param payload: payload bytes
    :return: hash bytes
    """
    return sha256(sha256(payload).digest()).digest()

def getdata_message(tx_type, header_hash):
    """
    Builds the getdata payload, per the Bitcoin protocol.
    :param tx_type: transaction type
    :param header_hash: hash of the desired block
    :return: getdata message bytes
    """
    # Identical to inv
    count = compactsize_t(1)
    entry_type = uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash)
    return count + entry_type + entry_hash


def getblocks_message(header_hash):
    """
    Builds the getblocks payload, per the Bitcoin protocol.
    :param header_hash: locator block hash, for peer to find
    :return: getblocks message bytes
    """
    version = uint32_t(VERSION)
    hash_count = compactsize_t(1)
    # Assuming we pass in an already computed sha256(sha256(block)) hash
    block_header_hashes = bytes.fromhex(header_hash)
    # Always ask for max number of blocks
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])




def build_message(command, payload):
    """
    Returns the complete message bytes (header + payload).
    :param command: message/command type
    :param payload: payload of the message
    :return: complete message bytes
    """
    return message_header(command, payload) + payload

def ping_message():
    """
    Build the ping payload, per the Bitcoin protocol.
    :return: ping message bytes
    """
    return uint64_t(random.getrandbits(64))


def message_header(command, payload):
    """
    Builds a Bitcoin message header.
    :param command: command/message type
    :param payload: payload of the message
    :return: message header bytes
    """
    magic = bytes.fromhex(START_STRING)
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = uint32_t(len(payload))
    check_sum = checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])


def version_message():
    """
    Builds the version message payload, per the Bitcoin protocol.
    :return: version message bytes
    """
    version = int32_t(VERSION)  # Version 70015
    services = uint64_t(0)  # Unnamed - not full node
    timestamp = int64_t(int(time.time()))  # Current UNIX epoch
    addr_recv_services = uint64_t(1)  # Full node
    addr_recv_ip_address = ipv6_from_ipv4(BTC_IP)  # Big endian
    addr_recv_port = uint16_t(BTC_PORT)
    addr_trans_services = uint64_t(0)  # Identical to services
    addr_trans_ip_address = ipv6_from_ipv4(MY_IP)  # Big endian
    addr_trans_port = uint16_t(BTC_PORT)
    nonce = uint64_t(0)
    user_agent_bytes = compactsize_t(0)  # 0 so no user agent field
    start_height = int32_t(0)
    relay = bool_t(False)

    return b''.join([version, services, timestamp, addr_recv_services,
                     addr_recv_ip_address, addr_recv_port, addr_trans_services,
                     addr_trans_ip_address, addr_trans_port, nonce,
                     user_agent_bytes, start_height, relay])

def compactsize_t(n):
    """
    Marshals compactsize data type.
    :param n: integer
    :return: marshalled compactsize integer
    """
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
    """Marshal to bool_t data type"""
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    """Marshal ipv4 string to ipv6"""
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    """Unmarshal ipv6 bytes to ipv4 string"""
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    """Marshal integer to unsigned, 8 bit"""
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    """Marshal integer to unsigned, 16 bit"""
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    """Marshal integer to signed, 32 bit"""
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    """Marshal integer to unsigned, 32 bit"""
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    """Marshal integer to signed, 64 bit"""
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    """Marshal integer to unsigned, 64 bit"""
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    """Unmarshal signed integer"""
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    """Unmarshal unsigned integer"""
    return int.from_bytes(b, byteorder='little', signed=False)

def swap_endian(b: bytes):
    """
    Swap the endianness of the given bytes. If little, swaps to big. If big,
    swaps to little.
    :param b: bytes to swap
    :return: swapped bytes
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
    elif command == 'sendcmpct':
        print_sendcmpct_message(payload)
    elif command == 'ping' or command == 'pong':
        print_ping_pong_message(payload)
    elif command == 'addr':
        print_addr_message(payload)
    elif command == 'feefilter':
        print_feefilter_message(payload)
    elif command == 'getblocks':
        print_getblocks_message(payload)
    elif command == 'inv' or command == 'getdata' or command == 'notfound':
        print_inv_message(payload, height)
    elif command == 'block':
        print_block_message(payload)
    return command

def print_block_message(payload):
    """
    Prints the contents of the block message.
    :param payload: block message payload
    """
    # Block header (80 bytes)
    version, prev_block, merkle_root, epoch_time, bits, nonce = \
        payload[:4], payload[4:36], payload[36:68], payload[68:72], \
        payload[72:76], payload[76:80]

    txn_count_bytes, txn_count = unmarshal_compactsize(payload[80:])
    txns = payload[80 + len(txn_count_bytes):]

    prefix = PREFIX * 2
    block_hash = swap_endian(hash(payload[:80]))
    print('{}{:32}\n{}{:32} block hash\n{}-'
          .format(prefix, block_hash.hex()[:32],
                  prefix, block_hash.hex()[32:], prefix))
    print('{}{:32} version: {}\n{}-'.
          format(prefix, version.hex(), unmarshal_int(version), prefix))
    prev_hash = swap_endian(prev_block)
    print('{}{:32}\n{}{:32} prev block hash\n{}-'
          .format(prefix, prev_hash.hex()[:32],
                  prefix, prev_hash.hex()[32:], prefix))
    merkle_hash = swap_endian(merkle_root)
    print('{}{:32}\n{}{:32} merkle root hash\n{}-'
          .format(prefix, merkle_hash.hex()[:32],
                  prefix, merkle_hash.hex()[32:], prefix))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",
                        gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} bits: {}'.format(prefix, bits.hex(), unmarshal_uint(bits)))
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), unmarshal_uint(nonce)))
    print('{}{:32} transaction count: {}'
          .format(prefix, txn_count_bytes.hex(), txn_count))
    print_transaction(txns)
    #for _ in range(txn_count):
        #print('{}{:32} txn: {}'.format(prefix, txns.hex(), unmarshal_uint(txns)))

def print_transaction(txn_bytes):
    #txn_bytes = txn_bytes.replace(b'*', b'')
    version = txn_bytes[:4]

    tx_in_count_bytes, tx_in_count = unmarshal_compactsize(txn_bytes[4:])
    tx_in_list = []
    i = 4 + len(tx_in_count_bytes)

    # TODO coinbase txn always first
    cb_txn, cb_script_bytes_count = parse_coinbase(txn_bytes[i:], version)
    tx_in_list.append(cb_txn)
    i += len(b''.join(cb_txn))

    for _ in range(1, tx_in_count):
        tx_in = parse_tx_in(txn_bytes[i:])
        tx_in_list.append(tx_in)
        i += len(b''.join(tx_in))

    tx_out_count_bytes, tx_out_count = unmarshal_compactsize(txn_bytes[i:])
    tx_out_list = []
    i += len(tx_out_count_bytes)
    for _ in range(tx_out_count):
        tx_out, pk_script_bytes_count = parse_tx_out(txn_bytes[i:])
        tx_out_list.append((tx_out, pk_script_bytes_count))
        i += len(b''.join(tx_out))

    lock_time = txn_bytes[i:i+4]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), unmarshal_uint(version)))
    print('{}{:32} input txn count: {}'.format(prefix, tx_in_count_bytes.hex(), tx_in_count))


    print('\n{}Coinbase transaction:'.format(prefix))
    print(prefix + '-' * 32)
    hash, index, script_bytes, cb_script, seq = cb_txn
    print('{}{:32}\n{}{:32} hash: {}\n{}-'.format(prefix, hash.hex()[:32], prefix, hash.hex()[32:], unmarshal_uint(hash), prefix))
    print('{}{:32} index: {}'.format(prefix, index.hex(), unmarshal_uint(index)))
    print('{}{:32} script bytes: {}'.format(prefix, script_bytes.hex(), cb_script_bytes_count))
    #print('{}{:32} height: {}'.format(prefix, height.hex(), unmarshal_uint(height)))

    print('{}{:32} coinbase script'.format(prefix, cb_script.hex()))
    print('{}{:32} sequence number'.format(prefix, seq.hex()))


    print('\n{}Output transactions:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} output txn count: {}'.format(prefix, tx_out_count_bytes.hex(), tx_out_count))


    for n, tx_out in enumerate(tx_out_list, start=1):
        print('\n{}Transaction {}:'.format(prefix, n))
        print(prefix + '-' * 32)
        value, pk_script_bytes, pk_script = tx_out[0]
        pk_script_bytes_count = tx_out[1]
        #value = swap_endian(value)
        satoshis = unmarshal_uint(value)
        global BLOCK_VALUE
        BLOCK_VALUE += satoshis
        btc = satoshis * 0.00000001
        print('{}{:32} value: {} satoshis = {} BTC'.format(prefix, value.hex(), satoshis, btc))
        print('{}{:32} public key script length: {}\n{}-'.format(prefix, pk_script_bytes.hex(), pk_script_bytes_count, prefix))
        #print('{}{:32} public key script'.format(prefix, pk_script.hex()))
        for j in range(0, pk_script_bytes_count * 2, 32):
            print('{}{:32}{}'.format(prefix, pk_script.hex()[j:j + 32], ' public key script\n{}-'.format(prefix) if j + 32 > pk_script_bytes_count * 2 else ''))

    print('{}{:32} lock time: {}'.format(prefix, lock_time.hex(), unmarshal_uint(lock_time)))
    if txn_bytes[i + 4:]:
        print('EXTRA: {}'.format(txn_bytes[i + 4:].hex()))




def parse_coinbase(cb_bytes, version=1):
    hash_null = cb_bytes[:32]
    index = cb_bytes[32:36]
    script_bytes, script_bytes_count = unmarshal_compactsize(cb_bytes[36:])
    i = 36 + len(script_bytes)

    # Version 1 doesn't require height parameter prior to block 227,836
    #if unmarshal_uint(version) > 1:
       # pass
        # TODO Get height

    cb_script = cb_bytes[i:i + script_bytes_count]
    sequence = cb_bytes[i + script_bytes_count: i + script_bytes_count + 4]
    return [hash_null, index, script_bytes, cb_script, sequence], script_bytes_count



    # hash_null = cb_bytes[:32]
    # index = cb_bytes[32:36]
    # script_bytes, script_bytes_count = unmarshal_compactsize(cb_bytes[36:])
    # i = 36 + len(script_bytes)
    # height_bytes = cb_bytes[i:i + 1]
    # i += 1
    # height = cb_bytes[i:i + 4] #FIXME or maybe uint
    # i += 4
    # cb_script = cb_bytes[i:i + script_bytes_count]
    # sequence = cb_bytes[i + script_bytes_count:i + script_bytes_count + 4]
    # return [hash_null, index, script_bytes, height_bytes, height, cb_script, sequence], script_bytes_count


def parse_tx_out(tx_out_bytes):
    value = tx_out_bytes[:8]
    pk_script_bytes, pk_script_bytes_count = unmarshal_compactsize(tx_out_bytes[8:])
    i = 8 + len(pk_script_bytes)
    pk_script = tx_out_bytes[i:i + pk_script_bytes_count]
    return [value, pk_script_bytes, pk_script], pk_script_bytes_count

def parse_tx_in(tx_in_bytes):
    prev_output = tx_in_bytes[:36]
    script_bytes, script_bytes_count = unmarshal_compactsize(tx_in_bytes[36:])
    i = len(script_bytes)
    sig_script = tx_in_bytes[i:i + script_bytes_count]  #FIXME char[]
    i += script_bytes_count
    sequence = tx_in_bytes[i:]
    return prev_output, script_bytes, sig_script, sequence


def print_inv_message(payload, height):
    """
    Prints the contents of the inv message.
    :param payload: inv message payload
    :param height: local blockchain height
    """
    count_bytes, count = unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i + 4], payload[i + 4:i + 36]
        inventory.append(inv_entry)
        i += 36

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory,
                                           start=height if height else 1):
        print('\n{}{:32} type: {}\n{}-'
              .format(prefix, tx_type.hex(), unmarshal_uint(tx_type), prefix))
        block_hash = swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} block #{} hash'
              .format(prefix, block_hash[:32], prefix, block_hash[32:], i))

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
        hash_hex = swap_endian(hash).hex()
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
    version, my_services, epoch_time, your_services = \
        b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = \
        b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = PREFIX * 2
    print('{}{:32} version {}'.format(prefix, version.hex(),
                                      unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",
                        gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(),
                                        ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(),
                                        unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(),
                                      ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(),
                                              uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(),
                                             str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(),
                                           unmarshal_uint(start_height)))
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


def get_last_block_hash(inv_bytes):
    return inv_bytes[len(inv_bytes) - 32:]


def update_current_height(block_list, curr_height):
    return curr_height + (len(block_list[-1]) - 27) // 36


def exchange_messages(bytes_to_send, sock, expected_bytes=None, height=None,
                      wait=False):
    """
    Exchanges messages with the Bitcoin node and prints the messages that
    are being sent and received.
    :param bytes_to_send: bytes to send to BTC node
    :param sock: TCP socket
    :param expected_bytes: number of bytes expecting to receive
    :param height: local blockchain height
    :param wait: whether to wait for a response
    :return:
    """
    print_message(bytes_to_send, 'send', height=height)
    #bytes_received = send_message(sock, bytes_to_send)

    sock.settimeout(0.5)
    bytes_received = b''
    try:
        sock.sendall(bytes_to_send)
        if expected_bytes:
            while len(bytes_received) < expected_bytes:
                bytes_received += sock.recv(MAX_SIZE)
        elif wait:
            while True:
                bytes_received += sock.recv(MAX_SIZE)

    except Exception as e:
        print('Failed to send message to {} at [{}]: {}'
              .format(BTC_PEER_ADDRESS, time.time(), str(e)))

    finally:
        print('\n****** Received {} bytes from BTC node {} ******'
              .format(len(bytes_received), BTC_PEER_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list

def send_getblocks_message(input_hash, btc_sock, current_height):
    """
    Sends the getblocks message to the Bitcoin node.
    :param input_hash: locator hash for the getblocks message
    :param btc_sock: TCP socket to the node
    :param current_height: local blockchain height
    :return: list of last 500 block headers, updated height
    """
    getblocks_bytes = build_message('getblocks',
                                    getblocks_message(input_hash.hex()))
    peer_inv = exchange_messages(getblocks_bytes, btc_sock,
                                 expected_bytes=18027,
                                 height=current_height + 1)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in
                        range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, current_height)
    return last_500_headers, current_height

def sat_to_btc(sat):
    return sat * 0.00000001

def get_transactions(block):
    txs_count_bytes = unmarshal_compactsize(block[104:])[0]
    return block[104 + len(txs_count_bytes):]

def change_price(block, n):

    old_block = block
    txn_count_bytes = unmarshal_compactsize(block[104:])[0]
    index = 104 + len(txn_count_bytes) + 4
    tx_in_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(tx_in_count_bytes)
    tx_in = parse_coinbase(block[index:], 1)[0]
    index += len(b''.join(tx_in))
    txn_out_count_bytes = unmarshal_compactsize(block[index:])[0]
    index += len(txn_out_count_bytes)

    old_merkle = block[60:92]
    calc_old_merkle = hash(block[104 + len(tx_in_count_bytes):])
    print('old merkle: ', old_merkle.hex())
    print('verify old merkle: ', calc_old_merkle.hex())

    #print(block[index:index + 8].hex())
    value = unmarshal_uint(block[index:index + 8])
    old_value = block[index:index + 8]
    #print(new_val_bytes.hex())
    #block[index:index + 8] = uint64_t(value * n)
    block = block.replace(block[index:index + 8], uint64_t(value * n))
    new_value = block[index:index + 8]
    #print('hash: {} -> {}'.format(hash(old_block).hex(), hash(block).hex()))
    print('value hex dump: {} -> {}'.format(old_value.hex(), new_value.hex()))
    print('reward change (factor of {}): {} BTC -> {} BTC'.format(n, sat_to_btc(value), sat_to_btc(unmarshal_uint(new_value))))
    # Calculate new merkle root

    block = block.replace(block[60:92], hash(block[104 + len(tx_in_count_bytes):]))
    new_merkle = block[60:92]
    calc_new_merkle = hash(block[104 + len(tx_in_count_bytes):])
    print('new merkle: ', new_merkle.hex())
    print('verify new merkle: ', calc_new_merkle.hex())
    return block

def thief_experiment(msg_list):
    global BLOCK_VALUE

    my_block = b''.join(msg_list)
    print('\nBitcoin thief experiment')
    btcs = BLOCK_VALUE * 0.00000001
    satoshis = BLOCK_VALUE
    print('Block #: {}'.format(BLOCK_NUMBER))
    print('-' * 8)
    print('value: {} BTC ({} satoshis)'.format(btcs, satoshis))
    BLOCK_VALUE *= 2
    thief_block = change_price(my_block, 2)
    thief_block = thief_block.replace(thief_block[20:HEADER_SIZE],
                                      checksum(thief_block[HEADER_SIZE:]))

    end = HEADER_SIZE + 80
    my_block_hash = swap_endian(hash(my_block[HEADER_SIZE:end])).hex()
    thief_block_hash = swap_endian(hash(thief_block[HEADER_SIZE:end])).hex()
    print('hash change: {} -> {}'.format(my_block_hash, thief_block_hash))
    print_message(thief_block,
                  'testing (expect merkle root and txn value change)')

def main():
    # b = swap_endian(bytes.fromhex('4e0105'))
    # print(b.hex())
    # sat = uint64_t(5000000000)
    # sat = swap_endian(sat)
    # print(sat.hex())
    # return
    # gen_header = get_block_header(genesis=True)
    # get_blocks = getblocks_message(gen_header.hex())
    # print(gen_header.hex())
    # print(hash(gen_header).hex())

    # expected = bytes.fromhex('fe28050b93faea61fa88c4c630f0e1f0a1c24d0082dd0e10d369e13212128f33')
    # m_hash = hash(bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d02fd04ffffffff0100f2052a01000000434104f5eeb2b10c944c6b9fbcfff94c35bdeecd93df977882babc7f3a2cf7f5c81d3b09a68db7f0e04f21de5d4230e75e6dbe7ad16eefe0d4325a62067dc6f369446aac00000000'))
    # print(expected.hex())
    # print(swap_endian(m_hash).hex())
    # byte_len = len(bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d02fd04ffffffff0100f2052a01000000434104f5eeb2b10c944c6b9fbcfff94c35bdeecd93df977882babc7f3a2cf7f5c81d3b09a68db7f0e04f21de5d4230e75e6dbe7ad16eefe0d4325a62067dc6f369446aac00000000'))
    # print(byte_len)

    global BLOCK_VALUE
    btc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    btc_sock.connect(BTC_PEER_ADDRESS)

    # Send version -> receive version, verack
    version_bytes = build_message('version', version_message())
    exchange_messages(version_bytes, btc_sock, expected_bytes=126)

    # Send verack -> receive sendheaders, sendcmpct, ping, addr, feefilter
    verack_bytes = build_message('verack', EMPTY_STRING)
    exchange_messages(verack_bytes, btc_sock, expected_bytes=202)


    # # Send ping -> receive pong
    ping_bytes = build_message('ping', ping_message())
    exchange_messages(ping_bytes, btc_sock, expected_bytes=32)

    # Send getblocks (starting from genesis) -> receive inv
    block_hash = swap_endian(BLOCK_GENESIS)
    current_height = 0
    last_500_blocks = []  # Store last 500 blocks from inv messages
    # Keep sending getblocks until inventory has the desired block number
    while current_height < BLOCK_NUMBER:
        last_500_blocks, current_height = send_getblocks_message(block_hash, btc_sock, current_height)
        block_hash = last_500_blocks[-1]

    # Retrieve block, send getdata for the block -> receive block message
    my_block_header = last_500_blocks[(BLOCK_NUMBER - 1) % 500]
    getdata_bytes = build_message('getdata', getdata_message(2, my_block_header.hex()))
    msg_list = exchange_messages(getdata_bytes, btc_sock, height=BLOCK_NUMBER, wait=True)

    # Double mining value and show new hash
    thief_experiment(msg_list)





    #print(my_block_header.hex())
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

    # # Send getblocks (after genesis block) -> receive inv
    # genesis_header_hash = hash(get_block_header(genesis=True))
    # genesis_header_hash = swap_endian(BLOCK_GENESIS)
    # getblocks_bytes = build_message('getblocks', getblocks_message(genesis_header_hash.hex()))
    # peer_inv = exchange_messages(getblocks_bytes, btc_sock, 18027, 0)
    # peer_inv_bytes = b''.join(peer_inv)
    # last_500_headers = [peer_inv_bytes[i:i + 32] for i in
    #                     range(31, len(peer_inv_bytes), 36)]
    # current_height = update_current_height(peer_inv, 0)
    #
    # # Send getblocks until we reach BLOCK_NUMBER -> receive inv
    # peer_inv_bytes = b''.join(peer_inv)
    # while current_height < BLOCK_NUMBER:
    #     print(current_height)
    #     header_hash = get_last_header(peer_inv_bytes)
    #     getblocks_bytes = build_message('getblocks', getblocks_message(header_hash.hex()))
    #     peer_inv = exchange_messages(getblocks_bytes, btc_sock, 18027, current_height + 1)
    #     peer_inv_bytes = b''.join(peer_inv)
    #     last_500_headers = [peer_inv_bytes[i:i + 32] for i in range(31, len(peer_inv_bytes), 36)]
    #     current_height = update_current_height(peer_inv, current_height)

if __name__ == '__main__':
    main()