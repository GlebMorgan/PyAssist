import os
import pickle
import time
import serial
import sys
from checksums import rfc1071, lrc
from utils import bytewise
import inspect


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
        zerobyte = b'' if (data.__len__() % 2) else b'\x00'
        packet = header + hcrc + data + dcrc + zerobyte + fcrc
        print(f"Packet: [{len(packet)}] {packet.hex()}")
        print(f"Data: [{len(packet[6:-2])}] {bytewise(packet[6:-2])}")
        s.write(packet)

        res = s.read(18)
        print(f"Reply packet: [{len(res)}] {res.hex()}")
        print(f"Reply data: [{len(res[6:-2])}] {bytewise(res[6:-2])}")

def testAssistPacket():

    s = serial.Serial(port='COM11', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_ODD, stopbits=1,
                      write_timeout=1, timeout=5)
    with s:
        time.sleep(1)
        packet = s.read(s.inWaiting())
        print(f"[{len(packet)}]: {bytewise(packet)}")
        print(f"[{len(packet[6:-2])}]: {bytewise(packet[6:-2])}")
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


if __name__ == '__main__':
    main()
    exit()
