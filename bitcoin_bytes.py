"""
Module for serializing and deserializing to/from bytes in order to construct
messages per the BitCoin messaging protocol.

Author: Francis Kogge
Date: 12/04/2021
"""


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
    """
    Unmarshals compactsize data type.
    :param n: bytes
    :return: raw bytes, integer
    """
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    """Marshal bool to unsigned, 8 bit"""
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