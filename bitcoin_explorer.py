"""
Bitcoin blockchain explorer: establishes a connection to a Bitcoin node using
version and version acknowledgement messages. Then retrieves a desired block
number using the getblocks message, and prints the transactions found inside
the block. There is also an experiment at the end where we change the reward
value of a transaction and print out the new merkle root and block hashes,
which would cause the block to get rejected by the rest of the Bitcoin network.

Author: Francis Kogge
Date: 12/05/2021
"""

import random
import time
import socket
import sys
import bitcoin_bytes as btc_bytes
from time import strftime, gmtime
from hashlib import sha256


''' 
IPs used for testing:
99.132.89.133
47.40.67.209   
104.129.171.121
'''
BTC_IP = '47.40.67.209'
BTC_PORT = 8333  # Mainnet
BTC_PEER_ADDRESS = (BTC_IP, BTC_PORT)
BTC_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
MAX_BLOCKS = 500  # Blocks from inv message
BLOCK_GENESIS = bytes.fromhex('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
MY_IP = '127.0.0.1'
START_STRING = bytes.fromhex('f9beb4d9')  # Magic bytes
EMPTY_STRING = ''.encode()  # Empty payload
HEADER_SIZE = 24  # For all Bitcoin message headers
COMMAND_SIZE = 12  # Message command length
VERSION = 70015
BLOCK_NUMBER = 6554  # Pick any block number
BUFFER_SIZE = 64000  # sock recv argument
PREFIX = '  '


def build_message(command, payload):
    """
    Returns the complete message bytes (header + payload).
    :param command: message/command type
    :param payload: payload of the message
    :return: complete message bytes
    """
    return message_header(command, payload) + payload


def version_message():
    """
    Builds the version message payload, per the Bitcoin protocol.
    :return: version message bytes
    """
    version = btc_bytes.int32_t(VERSION)  # Version 70015
    services = btc_bytes.uint64_t(0)  # Unnamed - not full node
    timestamp = btc_bytes.int64_t(int(time.time()))  # Current UNIX epoch
    addr_recv_services = btc_bytes.uint64_t(1)  # Full node
    addr_recv_ip_address = btc_bytes.ipv6_from_ipv4(BTC_IP)  # Big endian
    addr_recv_port = btc_bytes.uint16_t(BTC_PORT)
    addr_trans_services = btc_bytes.uint64_t(0)  # Identical to services
    addr_trans_ip_address = btc_bytes.ipv6_from_ipv4(MY_IP)  # Big endian
    addr_trans_port = btc_bytes.uint16_t(BTC_PORT)
    nonce = btc_bytes.uint64_t(0)
    user_agent_bytes = btc_bytes.compactsize_t(0)  # 0 so no user agent field
    start_height = btc_bytes.int32_t(0)
    relay = btc_bytes.bool_t(False)
    return b''.join([version, services, timestamp,
                     addr_recv_services, addr_recv_ip_address, addr_recv_port,
                     addr_trans_services, addr_trans_ip_address, addr_trans_port,
                     nonce, user_agent_bytes, start_height, relay])


def getdata_message(tx_type, header_hash):
    """
    Builds the getdata payload, per the Bitcoin protocol.
    :param tx_type: transaction type
    :param header_hash: hash of the desired block
    :return: getdata message bytes
    """
    # Identical to inv
    count = btc_bytes.compactsize_t(1)
    entry_type = btc_bytes.uint32_t(tx_type)
    entry_hash = bytes.fromhex(header_hash.hex())
    return count + entry_type + entry_hash


def getblocks_message(header_hash):
    """
    Builds the getblocks payload, per the Bitcoin protocol.
    :param header_hash: locator block hash, for peer to find
    :return: getblocks message bytes
    """
    version = btc_bytes.uint32_t(VERSION)
    hash_count = btc_bytes.compactsize_t(1)
    # Assuming we pass in an already computed sha256(sha256(block)) hash
    block_header_hashes = bytes.fromhex(header_hash.hex())
    # Always ask for max number of blocks
    stop_hash = b'\0' * 32
    return b''.join([version, hash_count, block_header_hashes, stop_hash])


def ping_message():
    """
    Build the ping payload, per the Bitcoin protocol.
    :return: ping message bytes
    """
    return btc_bytes.uint64_t(random.getrandbits(64))


def message_header(command, payload):
    """
    Builds a Bitcoin message header.
    :param command: command/message type
    :param payload: payload of the message
    :return: message header bytes
    """
    magic = START_STRING
    command_name = command.encode('ascii')
    while len(command_name) < COMMAND_SIZE:
        command_name += b'\0'
    payload_size = btc_bytes.uint32_t(len(payload))
    check_sum = checksum(payload)
    return b''.join([magic, command_name, payload_size, check_sum])


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


def sat_to_btc(sat):
    """Converts satoshis to BTC"""
    return sat * 0.00000001


def btc_to_sat(btc):
    """Converts BTC to satoshis"""
    return btc * 10e7


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
        header_hash = btc_bytes.swap_endian(hash(payload[:80])).hex() if command == 'block' else ''
        print('{}{} {}'.format(PREFIX, command.upper(), header_hash))
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


def print_inv_message(payload, height):
    """
    Prints the contents of the inv message.
    :param payload: inv message payload
    :param height: local blockchain height
    """
    count_bytes, count = btc_bytes.unmarshal_compactsize(payload)
    i = len(count_bytes)
    inventory = []
    for _ in range(count):
        inv_entry = payload[i: i + 4], payload[i + 4:i + 36]
        inventory.append(inv_entry)
        i += 36

    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, count_bytes.hex(), count))
    for i, (tx_type, tx_hash) in enumerate(inventory, start=height if height else 1):
        print('\n{}{:32} type: {}\n{}-'
              .format(prefix, tx_type.hex(), btc_bytes.unmarshal_uint(tx_type), prefix))
        block_hash = btc_bytes.swap_endian(tx_hash).hex()
        print('{}{:32}\n{}{:32} block #{} hash'.format(prefix, block_hash[:32], prefix, block_hash[32:], i))


def print_getblocks_message(payload):
    """
    Prints contents of the getblocks message.
    :param payload: getblocks message payload
    """
    version = payload[:4]
    hash_count_bytes, hash_count = btc_bytes.unmarshal_compactsize(payload[4:])
    i = 4 + len(hash_count_bytes)
    block_header_hashes = []
    for _ in range(hash_count):
        block_header_hashes.append(payload[i:i + 32])
        i += 32
    stop_hash = payload[i:]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), btc_bytes.unmarshal_uint(version)))
    print('{}{:32} hash count: {}'.format(prefix, hash_count_bytes.hex(), hash_count))
    for hash in block_header_hashes:
        hash_hex = btc_bytes.swap_endian(hash).hex()
        print('\n{}{:32}\n{}{:32} block header hash # {}: {}'
              .format(prefix, hash_hex[:32], prefix, hash_hex[32:], 1, btc_bytes.unmarshal_uint(hash)))
    stop_hash_hex = stop_hash.hex()
    print('\n{}{:32}\n{}{:32} stop hash: {}'
          .format(prefix, stop_hash_hex[:32], prefix, stop_hash_hex[32:], btc_bytes.unmarshal_uint(stop_hash)))


def print_feefilter_message(feerate):
    """
    Prints contents of the feefilter message.
    :param feerate: feefilter message payload
    """
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, feerate.hex(), btc_bytes.unmarshal_uint(feerate)))


def print_addr_message(payload):
    """
    Prints contents of the addr message.
    :param payload: addr message payload
    """
    ip_count_bytes, ip_addr_count = btc_bytes.unmarshal_compactsize(payload)
    i = len(ip_count_bytes)
    epoch_time, services, ip_addr, port = \
        payload[i:i + 4], payload[i + 4:i + 12], \
        payload[i + 12:i + 28], payload[i + 28:]
    prefix = PREFIX * 2
    print('{}{:32} count: {}'.format(prefix, ip_count_bytes.hex(), ip_addr_count))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(btc_bytes.unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} services: {}'.format(prefix, services.hex(), btc_bytes.unmarshal_uint(services)))
    print('{}{:32} host: {}'.format(prefix, ip_addr.hex(), btc_bytes.ipv6_to_ipv4(ip_addr)))
    print('{}{:32} port: {}'.format(prefix, port.hex(), btc_bytes.unmarshal_uint(port)))


def print_ping_pong_message(nonce):
    """
    Print contents of ping/pong message.
    :param nonce: payload (always nonce)
    """
    prefix = PREFIX * 2
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), btc_bytes.unmarshal_uint(nonce)))


def print_sendcmpct_message(payload):
    """
    Prints contents of the sendcmpct message.
    :param payload: sendcmpct message payload
    """
    announce, version = payload[:1], payload[1:]
    prefix = PREFIX * 2
    print('{}{:32} announce: {}'.format(prefix, announce.hex(), bytes(announce) != b'\0'))
    print('{}{:32} version: {}'.format(prefix, version.hex(), btc_bytes.unmarshal_uint(version)))


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param b: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = btc_bytes.unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = PREFIX * 2
    print('{}{:32} version {}'.format(prefix, version.hex(), btc_bytes.unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(btc_bytes.unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), btc_bytes.ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), btc_bytes.unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), btc_bytes.ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), btc_bytes.unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'
          .format(prefix, start_height.hex(), btc_bytes.unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message,
                           if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = btc_bytes.unmarshal_uint(payload_size)
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


def print_block_message(payload):
    """
    Prints the contents of the block message.
    :param payload: block message payload
    """
    # Block header (80 bytes)
    version, prev_block, merkle_root, epoch_time, bits, nonce = \
        payload[:4], payload[4:36], payload[36:68], payload[68:72], payload[72:76], payload[76:80]

    txn_count_bytes, txn_count = btc_bytes.unmarshal_compactsize(payload[80:])
    txns = payload[80 + len(txn_count_bytes):]

    prefix = PREFIX * 2
    print('{}{:32} version: {}\n{}-'
          .format(prefix, version.hex(), btc_bytes.unmarshal_int(version), prefix))
    prev_hash = btc_bytes.swap_endian(prev_block)
    print('{}{:32}\n{}{:32} prev block hash\n{}-'
          .format(prefix, prev_hash.hex()[:32], prefix, prev_hash.hex()[32:], prefix))
    merkle_hash = btc_bytes.swap_endian(merkle_root)
    print('{}{:32}\n{}{:32} merkle root hash\n{}-'
          .format(prefix, merkle_hash.hex()[:32], prefix, merkle_hash.hex()[32:], prefix))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(btc_bytes.unmarshal_int(epoch_time)))
    print('{}{:32} epoch time: {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} bits: {}'.format(prefix, bits.hex(), btc_bytes.unmarshal_uint(bits)))
    print('{}{:32} nonce: {}'.format(prefix, nonce.hex(), btc_bytes.unmarshal_uint(nonce)))
    print('{}{:32} transaction count: {}'.format(prefix, txn_count_bytes.hex(), txn_count))
    print_transaction(txns)


def print_transaction(txn_bytes):
    """
    Prints the contents of the transactions portion of a block.
    :param txn_bytes: transaction bytes from the block
    """
    # Parse version and transaction input count bytes
    version = txn_bytes[:4]
    tx_in_count_bytes, tx_in_count = btc_bytes.unmarshal_compactsize(txn_bytes[4:])
    i = 4 + len(tx_in_count_bytes)

    # Parse coinbase bytes
    cb_txn, cb_script_bytes_count = parse_coinbase(txn_bytes[i:], version)
    tx_in_list = [(cb_txn, cb_script_bytes_count)]
    i += len(b''.join(cb_txn))

    # Parse transaction input bytes
    for _ in range(1, tx_in_count):
        tx_in, script_bytes_count = parse_tx_in(txn_bytes[i:])
        tx_in_list.append((tx_in, script_bytes_count))
        i += len(b''.join(tx_in))

    # Parse transaction output count bytes
    tx_out_count_bytes, tx_out_count = btc_bytes.unmarshal_compactsize(txn_bytes[i:])
    tx_out_list = []
    i += len(tx_out_count_bytes)

    # Parse transaction output bytes
    for _ in range(tx_out_count):
        tx_out, pk_script_bytes_count = parse_tx_out(txn_bytes[i:])
        tx_out_list.append((tx_out, pk_script_bytes_count))
        i += len(b''.join(tx_out))

    lock_time = txn_bytes[i:i+4]

    prefix = PREFIX * 2
    print('{}{:32} version: {}'.format(prefix, version.hex(), btc_bytes.unmarshal_uint(version)))

    print('\n{}Transaction Inputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} input txn count: {}'.format(prefix, tx_in_count_bytes.hex(), tx_in_count))
    print_transaction_inputs(tx_in_list)

    print('\n{}Transaction Outputs:'.format(prefix))
    print(prefix + '-' * 32)
    print('{}{:32} output txn count: {}'.format(prefix, tx_out_count_bytes.hex(), tx_out_count))
    print_transaction_outputs(tx_out_list)

    print('{}{:32} lock time: {}'.format(prefix, lock_time.hex(), btc_bytes.unmarshal_uint(lock_time)))
    if txn_bytes[i + 4:]:
        print('EXTRA: {}'.format(txn_bytes[i + 4:].hex()))


def print_transaction_inputs(tx_in_list):
    """
    Prints the transaction inputs from the transactions portion of the block.
    :param tx_in_list: list of input transactions
    """
    prefix = PREFIX * 2
    for i, tx_in in enumerate(tx_in_list, start=1):
        print('\n{}Transaction {}{}:'.format(prefix, i, ' (Coinbase)' if i == 1 else ''))
        print(prefix + '*' * 32)
        hash, index, script_bytes, sig_script, seq = tx_in[0]
        script_bytes_count = tx_in[1]
        print('{}{:32}\n{}{:32} hash\n{}-'.format(prefix, hash.hex()[:32], prefix, hash.hex()[32:], prefix))
        print('{}{:32} index: {}'.format(prefix, index.hex(), btc_bytes.unmarshal_uint(index)))
        print('{}{:32} script bytes: {}'.format(prefix, script_bytes.hex(), script_bytes_count))
        print('{}{:32} {}script'.format(prefix, sig_script.hex(), 'coinbase ' if i == 1 else ''))
        print('{}{:32} sequence number'.format(prefix, seq.hex()))


def print_transaction_outputs(tx_out_list):
    """
    Prints the transaction outputs from the transactions portion of the block.
    :param tx_out_list: list of output transactions
    """
    prefix = PREFIX * 2
    for i, tx_out in enumerate(tx_out_list, start=1):
        print('\n{}Transaction {}:'.format(prefix, i))
        print(prefix + '*' * 32)
        value, pk_script_bytes, pk_script = tx_out[0]
        pk_script_bytes_count = tx_out[1]
        satoshis = btc_bytes.unmarshal_uint(value)
        btc = sat_to_btc(satoshis)
        print('{}{:32} value: {} satoshis = {} BTC'.format(prefix, value.hex(), satoshis, btc))
        print('{}{:32} public key script length: {}\n{}-'
              .format(prefix, pk_script_bytes.hex(), pk_script_bytes_count, prefix))
        for j in range(0, pk_script_bytes_count * 2, 32):
            print('{}{:32}{}' .format(prefix, pk_script.hex()[j:j + 32],
                                      ' public key script\n{}-'.format(prefix)
                                      if j + 32 > pk_script_bytes_count * 2 else ''))


def parse_coinbase(cb_bytes, version):
    """
    Parses the bytes of a coinbase transaction.
    :param cb_bytes: coinbase transaction bytes
    :param version: version number of the block being handled
    :return: list of the coinbase bytes, number of bytes in the script
    """
    hash_null = cb_bytes[:32]
    index = cb_bytes[32:36]
    script_bytes, script_bytes_count = btc_bytes.unmarshal_compactsize(cb_bytes[36:])
    i = 36 + len(script_bytes)

    height = None
    # Version 1 doesn't require height parameter prior to block 227,836
    if btc_bytes.unmarshal_uint(version) > 1:
        height = cb_bytes[i:i + 4]
        i += 4

    cb_script = cb_bytes[i:i + script_bytes_count]
    sequence = cb_bytes[i + script_bytes_count: i + script_bytes_count + 4]

    if height:
        return [hash_null, index, script_bytes, height, cb_script, sequence], script_bytes_count
    else:
        return [hash_null, index, script_bytes, cb_script, sequence], script_bytes_count


def parse_tx_out(tx_out_bytes):
    """
    Parses the transaction output bytes of a transaction.
    :param tx_out_bytes: transaction output bytes
    :return: list of the tx out bytes, number of bytes in the script
    """
    value = tx_out_bytes[:8]
    pk_script_bytes, pk_script_bytes_count = btc_bytes.unmarshal_compactsize(tx_out_bytes[8:])
    i = 8 + len(pk_script_bytes)
    pk_script = tx_out_bytes[i:i + pk_script_bytes_count]
    return [value, pk_script_bytes, pk_script], pk_script_bytes_count


def parse_tx_in(tx_in_bytes):
    """
    Parses the transaction input bytes of a transaction.
    :param tx_in_bytes: transaction input bytes
    :return: list of the tx in bytes, number of bytes in the script
    """
    hash = tx_in_bytes[:32]
    index = tx_in_bytes[32:36]
    script_bytes, script_bytes_count = btc_bytes.unmarshal_compactsize(tx_in_bytes[36:])
    i = 36 + len(script_bytes)
    sig_script = tx_in_bytes[i:i + script_bytes_count]
    sequence = tx_in_bytes[i + script_bytes_count:]
    return [hash, index, script_bytes, sig_script, sequence], script_bytes_count


def split_message(peer_msg_bytes):
    """
    Splits the bytes into a list of each individual message.
    :param peer_msg_bytes: message bytes to split
    :return: list of each message
    """
    msg_list = []
    while peer_msg_bytes:
        payload_size = btc_bytes.unmarshal_uint(peer_msg_bytes[16:20])
        msg_size = HEADER_SIZE + payload_size
        msg_list.append(peer_msg_bytes[:msg_size])
        # Discard to move onto next message
        peer_msg_bytes = peer_msg_bytes[msg_size:]
    return msg_list


def get_last_block_hash(inv_bytes):
    """
    Get the last block hash from an inv message.
    :param inv_bytes: inv message bytes
    :return: last block hash
    """
    return inv_bytes[len(inv_bytes) - 32:]


def update_current_height(block_list, curr_height):
    """
    Update the current height of our local block chain.
    :param block_list: list of blocks
    :param curr_height: before height
    :return: after height
    """
    return curr_height + (len(block_list[-1]) - 27) // 36


def exchange_messages(bytes_to_send, expected_bytes=None, height=None, wait=False):
    """
    Exchanges messages with the Bitcoin node and prints the messages that
    are being sent and received.
    :param bytes_to_send: bytes to send to BTC node
    :param expected_bytes: number of bytes expecting to receive
    :param height: local blockchain height
    :param wait: whether to wait for a response
    :return: list of the message bytes received
    """
    print_message(bytes_to_send, 'send', height=height)
    BTC_SOCK.settimeout(0.5)
    bytes_received = b''

    try:
        BTC_SOCK.sendall(bytes_to_send)

        if expected_bytes:
            # Message size is fixed: receive until byte sizes match
            while len(bytes_received) < expected_bytes:
                bytes_received += BTC_SOCK.recv(BUFFER_SIZE)
        elif wait:
            # Message size could vary: wait until timeout to receive all bytes
            while True:
                bytes_received += BTC_SOCK.recv(BUFFER_SIZE)

    except Exception as e:
        print('\nNo bytes left to receive from {}: {}'
              .format(BTC_PEER_ADDRESS, str(e)))

    finally:
        print('\n****** Received {} bytes from BTC node {} ******'
              .format(len(bytes_received), BTC_PEER_ADDRESS))
        peer_msg_list = split_message(bytes_received)
        for msg in peer_msg_list:
            print_message(msg, 'receive', height)
        return peer_msg_list


def send_getblocks_message(input_hash, current_height):
    """
    Helper method for sending the getblocks message to the Bitcoin node.
    :param input_hash: locator hash for the getblocks message
    :param current_height: local blockchain height
    :return: list of last 500 block headers, updated height
    """
    getblocks_bytes = build_message('getblocks', getblocks_message(input_hash))
    peer_inv = exchange_messages(getblocks_bytes, expected_bytes=18027, height=current_height + 1)
    peer_inv_bytes = b''.join(peer_inv)
    last_500_headers = [peer_inv_bytes[i:i + 32] for i in range(31, len(peer_inv_bytes), 36)]
    current_height = update_current_height(peer_inv, current_height)
    return last_500_headers, current_height


def peer_height_from_version(vsn_bytes):
    """
    Retrieves the height of the peer's blockchain using the start_height bytes
    from their version message.
    :param vsn_bytes: peer version message bytes
    :return: peer blockchain height
    """
    return btc_bytes.unmarshal_uint(vsn_bytes[-5:-1])


def change_block_value(block, block_number, new_amt):
    """
    Change the satoshi reward value of the block.
    :param block: block to change
    :param new_amt: new reward value in satoshis
    :return: altered block
    """
    # Jump to the value index in the block
    txn_count_bytes = btc_bytes.unmarshal_compactsize(block[104:])[0]
    index = 104 + len(txn_count_bytes)
    version = block[index:index + 4]
    index += 4
    tx_in_count_bytes = btc_bytes.unmarshal_compactsize(block[index:])[0]
    index += len(tx_in_count_bytes)
    tx_in = parse_coinbase(block[index:], version)[0]
    index += len(b''.join(tx_in))
    txn_out_count_bytes = btc_bytes.unmarshal_compactsize(block[index:])[0]
    index += len(txn_out_count_bytes)

    # Display old value
    old_value_bytes = block[index:index + 8]
    old_value = btc_bytes.unmarshal_uint(old_value_bytes)
    print('Block {}: change value from {} BTC to {} BTC'
          .format(block_number, sat_to_btc(old_value), sat_to_btc(new_amt)))
    print('-' * 41)
    print('{:<24}'.format('old value:') + '{} BTC = {} satoshis'.format(sat_to_btc(old_value), old_value))

    # Verify old merkle hash
    old_merkle = btc_bytes.swap_endian(block[60:92])
    calc_old_merkle = btc_bytes.swap_endian(hash(block[104 + len(tx_in_count_bytes):]))
    print('{:<24}'.format('old merkle hash:') + old_merkle.hex())
    print('{:<24}'.format('verify old merkle hash:') + 'hash(txn) = {}'.format(calc_old_merkle.hex()))
    old_hash = btc_bytes.swap_endian(hash(block[HEADER_SIZE:HEADER_SIZE + 80]))
    print('{:<24}'.format('old block hash:') + old_hash.hex())

    print('*' * 16)

    # Change the value bytes in the block
    block = block.replace(block[index:index + 8], btc_bytes.uint64_t(new_amt))
    new_value_bytes = block[index:index + 8]
    new_value = btc_bytes.unmarshal_uint(new_value_bytes)
    print('{:<24}'.format('new value:') + '{} BTC = {} satoshis'.format(sat_to_btc(new_value), new_value))

    # Calculate and display new merkle root
    calc_new_merkle = hash(block[104 + len(tx_in_count_bytes):])
    block = block.replace(block[60:92], calc_new_merkle)
    new_merkle = btc_bytes.swap_endian(block[60:92])
    calc_new_merkle = btc_bytes.swap_endian(calc_new_merkle)
    print('{:<24}'.format('new merkle:') + new_merkle.hex())
    print('{:<24}'.format('verify new merkle:') + 'hash(txn) = {}'.format(calc_new_merkle.hex()))

    # Calculate and display new block hash
    new_hash = btc_bytes.swap_endian(hash(block[HEADER_SIZE:HEADER_SIZE + 80]))
    print('{:<24}'.format('new block hash:') + new_hash.hex())
    print('-' * 32)
    return block


def thief_experiment(my_block, block_number, last_500_blocks, new_value):
    """
    Experiment with being a Bitcoin thief by changing the value of a transaction
    then showing how the new block would not get accepted by the Bitcoin
    network, due to changes to the merkle root and block hash.
    :param my_block: my block to change value of
    :param last_500_blocks: list of last 500 block headers retrieved
    :param new_value: BTC value to change the block value to
    """
    print('\nBitcoin thief experiment')
    print('*' * 64 + '\n')
    btcs = new_value
    satoshis = btc_to_sat(btcs)

    # Change block value, merkle hash, and update checksum
    thief_block = change_block_value(my_block, block_number, satoshis)
    thief_block = thief_block.replace(thief_block[20:HEADER_SIZE], checksum(thief_block[HEADER_SIZE:]))

    # Print fields of the new thief block
    end = HEADER_SIZE + 80
    thief_block_hash = btc_bytes.swap_endian(hash(thief_block[HEADER_SIZE:end])).hex()
    print_message(thief_block, '*** TEST (value has changed) *** ')

    # Get the next block and verify it's prev block hash doesn't match the
    # new hash of the altered/thief block
    print('\nBlock # {} data: '.format(block_number + 1))
    next_block_hash = last_500_blocks[(block_number) % 500]
    getdata_msg = build_message('getdata', getdata_message(2, next_block_hash))
    next_block = exchange_messages(getdata_msg, wait=True)
    next_block = b''.join(next_block)
    prev_block_hash = btc_bytes.swap_endian(next_block[28:60]).hex()
    print('\nBlock {} prev block hash : {}'.format(block_number + 1, prev_block_hash))
    print('Block {} altered hash: {}'.format(block_number, thief_block_hash))
    print('{} == {} -> {} -> reject!'.format(prev_block_hash, thief_block_hash,
                                             prev_block_hash == thief_block_hash))


def main():
    """Executes program from main entry point."""
    if len(sys.argv) != 2:
        print('Usage: bitcoin_explorer.py BLOCK_NUMBER')
        exit(1)

    # Block number from command line argument
    block_number = int(sys.argv[1])

    with BTC_SOCK:
        # Establish connection with Bitcoin node
        BTC_SOCK.connect(BTC_PEER_ADDRESS)

        # Send version -> receive version, verack
        version_bytes = build_message('version', version_message())
        peer_vsn_bytes = exchange_messages(version_bytes, expected_bytes=126)[0]
        peer_height = peer_height_from_version(peer_vsn_bytes)

        # Send verack -> receive sendheaders, sendcmpct, ping, addr, feefilter
        verack_bytes = build_message('verack', EMPTY_STRING)
        exchange_messages(verack_bytes, expected_bytes=202)

        # Send ping -> receive pong
        ping_bytes = build_message('ping', ping_message())
        exchange_messages(ping_bytes, expected_bytes=32)

        # Check supplied block number against peer's blockchain height
        if block_number > peer_height:
            print('\nCould not retrieve block {}: max height is {}'.format(block_number, peer_height))
            exit(1)

        # Send getblocks (starting from genesis) -> receive inv
        block_hash = btc_bytes.swap_endian(BLOCK_GENESIS)
        current_height = 0
        # Store last 500 blocks from inv messages
        last_500_blocks = []
        # Keep sending getblocks until inventory has the desired block number
        while current_height < block_number:
            last_500_blocks, current_height = send_getblocks_message(block_hash, current_height)
            block_hash = last_500_blocks[-1]

        # Retrieve block, send getdata for the block -> receive block message
        my_block_hash = last_500_blocks[(block_number - 1) % 500]
        getdata_bytes = build_message('getdata', getdata_message(2, my_block_hash))
        msg_list = exchange_messages(getdata_bytes, height=block_number, wait=True)
        my_block = b''.join(msg_list)

        # Pick new reward value for the bitcoin
        thief_experiment(my_block, block_number, last_500_blocks, 4000)


if __name__ == '__main__':
    main()
