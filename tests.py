import os
import pickle
import time

import math
import serial
import sys
from checksums import rfc1071, lrc
from utils import bytewise
import inspect

'''
(http://plaintexttools.github.io/plain-text-table)
'''


def wrap(msg, adr):
    # 'msg' includes parity bit CRC!
    datalen = len(msg) # 10
    assert (datalen <= 0xFFF)
    assert (adr <= 0xFF)
    zerobyte = b'\x00' if (datalen % 2) else b''
    datalen += 2*len(zerobyte)
    header = b'\x5A' + adr.to_bytes(1, 'little') + (datalen//2 | (len(zerobyte) << 15)).to_bytes(2, 'little')
    packet = header + rfc1071(header) + msg + zerobyte
    return packet + rfc1071(packet)


def testDataLengthField(b_msg):
    dataLen = len(b_msg) # 0x1000 - max number that fits into wrapper LENGTH field
    dataLenField = dataLen.to_bytes(2, 'little')

    checkDataLength = (dataLenField[1] & 0x0F) * 0x100 + dataLenField[0]
    print(checkDataLength, dataLen)


def testCheckChannel():
    s = serial.Serial(port='COM7', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_NONE, stopbits=1,
                      write_timeout=1, timeout=1)

    with s:
        d1 = '0101 AA BB CC DD EE FF 88 99'
        d2 = '0102'
        h1 = '5A 0C 06 80'
        data = bytes.fromhex(d1)
        header = bytes.fromhex(h1)

        hcrc = rfc1071(header)
        dcrc = lrc(data)
        fcrc = rfc1071(header+data)
        zerobyte = b'' if (len(data) % 2) else b'\x00'
        packet = header + hcrc + data + dcrc + zerobyte + fcrc
        print(f"Packet: [{len(packet)}] {packet.hex()}")
        print(f"Data: [{len(packet[6:-2])}] {bytewise(packet[6:-2])}")
        s.write(packet)

        res = s.read(s.inWaiting())
        print(f"Reply packet: [{len(res)}] {res.hex()}")
        print(f"Reply data: [{len(res[6:-2])}] {bytewise(res[6:-2])}")


def testCheckChannelWrapped():
    s = serial.Serial(port='COM7', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_NONE, stopbits=1,
                      write_timeout=1, timeout=1)

    d1 = '0101 AA BB CC DD EE FF 88 99'
    d2 = '0101 a8 ab af aa ac ab a3 aa'
    d3 = '0102'
    d4 = '0103'
    data = bytes.fromhex(d1)
    packet = wrap(data+lrc(data), adr=12)
    with s:
        print(f"Packet: [{len(packet)}] {packet.hex()}")
        print(f"Data: [{len(packet[6:-2])}] {bytewise(packet[6:-2])}")
        s.write(packet)
        time.sleep(0.05)
        res = s.read(s.in_waiting)
        print(f"Reply packet: [{len(res)}] {res.hex()}")
        print(f"Reply data: [{len(res[6:-2])}] {bytewise(res[6:-2])}")
        if(data == b'\x01\x03'): print(f"String: {res[7:-4].decode('utf-8')}")

def testAssistPacket():
    s = serial.Serial(port='COM11', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_ODD, stopbits=1,
                      write_timeout=1, timeout=5)
    with s:
        time.sleep(1)
        packet = s.read(s.inWaiting())
        print(f"[{len(packet)}]: {bytewise(packet)}")
        print(f"[{len(packet[6:-2])}]: {bytewise(packet[6:-2])}")
        # eAssist check channel:
        # 5a 0c 06 80 9f 73 01 01 a8 ab af aa ac ab a3 aa 08 00 4e 52
        #                   01 01 a8 ab af aa ac ab a3 aa 08 00
        # ans:                 00 a8 ab af aa ac ab a3 aa 08


def test_return_in_gen():
    def gen_with_return():
        for i in range(8):
            yield(f"iter {i}")
            if (i == 5):
                return f"i=={i}"
    g = gen_with_return()
    for i in range(10): print(g.__next__())


def main():
    testCheckChannelWrapped()


if __name__ == '__main__':
    main()
    exit()
