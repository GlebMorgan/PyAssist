import os
import pickle
import time

import math
import serial
import sys

import struct
from checksums import rfc1071, lrc
from timer import Timer
from utils import bytewise, bitwise
from math import ceil
import bits
import inspect

'''
(http://plaintexttools.github.io/plain-text-table)
'''


# 1           2     3:4           5:6         7:8       9:...         -3    -2:-1
# StartByte - ADR - Length|EVEN - HeaderRFC - COMMAND - CommandData - LRC - PacketRFC


def wrap(msg, adr):
    # 'msg' includes parity bit CRC!
    datalen = len(msg)
    assert(datalen <= 0xFFF)
    assert(adr <= 0xFF)
    zerobyte = b'\x00' if (datalen % 2) else b''
    datalen += 2*len(zerobyte)
    header = b'\x5A' + adr.to_bytes(1, 'little') + (datalen//2 | (len(zerobyte) << 15)).to_bytes(2, 'little')
    packet = header + rfc1071(header) + msg + zerobyte
    return packet + rfc1071(packet)


def wrap_pack(msg, adr):
    # 'msg' includes parity bit CRC!
    datalen = len(msg) # 'datalen' - size in bytes
    assert(datalen <= 0xFFF)
    assert(adr <= 0xFF)
    addZeroByte = datalen % 2
    header = struct.pack(
            '< B B H', 0x5A, adr, int(ceil(datalen/2)) | (bits.set(bits=15)*addZeroByte)
    ) # 'datalen/2' - size in 16-bit words
    packet = header + rfc1071(header) + msg + b'\x00'*addZeroByte # Where do I add zerobyte? Here or 1 row below?
    return packet + rfc1071(packet)


def unwrap(packet):

    # verify packet integrity
    if (not packet): return packet
    if (packet[0] != 0x5A): print(f"Error: bad start byte '{packet[0]:X}'")
    if (int.from_bytes(rfc1071(packet[:6]), 'big')): print("Error: bad header checksum")
    if (int.from_bytes(rfc1071(packet), 'big')): print("Error: bad packet checksum")

    # unwrap
    fields = struct.unpack('< B B H H', packet[:6]) # unpack header (fixed size - 6 bytes)
    if (fields[1] != 0): print("Error: wrong address")
    datalen = (fields[2] & 0x0FFF) * 2 # size in bytes
    zerobyte = (fields[2] & 0x8000) >> 15 # extract EVEN flag (b15 in LSB / b7 in MSB)
    print(f"Zbyte: {zerobyte == 1}")
    return packet[6:6+datalen-zerobyte]


# -------------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':

    def testDataLengthField(b_msg):
        dataLen = len(b_msg)  # 0x1000 - max number that fits into wrapper LENGTH field
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
            fcrc = rfc1071(header + data)
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
        packet = wrap(data + lrc(data), adr=12)
        with s:
            print(f"Packet [{len(packet)}]: {packet.hex()}")
            print(f"Data [{len(packet[6:-2])}]: {bytewise(packet[6:-2])}")
            s.write(packet)
            time.sleep(0.05)
            res = s.read(s.in_waiting)
            print(f"Reply packet [{len(res)}]: {res.hex()}")
            print(f"Reply data [{len(res[6:-2])}]: {bytewise(res[6:-2])}")
            if (data == b'\x01\x03'): print(f"String: {res[7:-4].decode('utf-8')}")


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
                yield (f"iter {i}")
                if (i == 5):
                    return f"i=={i}"

        g = gen_with_return()
        for i in range(10): print(g.__next__())


    def test_wrap_perf():
        d1 = '0101 AA BB CC DD EE FF 88 99'
        d2 = '0101 a8 ab af aa ac ab a3 aa'
        d3 = '0102'
        d4 = '0103'
        data = bytes.fromhex(d1)
        with Timer("old"):
            for i in range(100_000): packet = wrap(data + lrc(data), adr=12)
        with Timer("new"):
            for i in range(100_000): packet2 = wrap_pack(data + lrc(data), adr=12)
        print(packet)
        print(packet2)
        print(packet2 == packet)


    samplepacket = b'Z\x0c\x06\x80\x9fs\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\x00\x0f\xcc'
    samplereply = b'Z\x00\x05\x00\xa0\xff\x00\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\xcd\x10'

    def test_unwrap():
        d1 = '0101 AA BB CC DD EE FF 88 99'
        d2 = '0101 a8 ab af aa ac ab a3 aa'
        d3 = '0102'
        d4 = '0103'
        data = bytes.fromhex(d1)
        packet = wrap(data + lrc(data), adr=12)
        with Timer("old"):
            for i in range(100_000): redata = unwrap(samplereply)
        validdata = b'\x00\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00'
        print(redata)
        print(validdata)
        print(redata == validdata)
        print(rfc1071(samplereply))

    def test_send_command():
        class CommandError(RuntimeError): pass

        s = serial.Serial(port='COM2', baudrate=921600,
                          bytesize=8, parity=serial.PARITY_NONE, stopbits=1,
                          write_timeout=1, timeout=1)

        cMsgs = {
            'chch': '0101 AA BB CC DD EE FF 88 99', #check channel
            'r': '0102', # reset
            'di': '0103', # device info
            'sm+': '010401', # scan mode on
            'sm-': '010400', # scan mode off
            'st': '0105', # selftest
            'ss': '0106', # save settings
            'tch': '0107 11 22 33 00', # test channel
            'tch-0': '0107 11 22 33 44', # test channel (without '0' ending)

        }
        commands = cMsgs.keys()

        exitcommands = ('quit', 'exit', 'q', 'e')
        if (any(value in cMsgs for value in exitcommands)):
            raise AttributeError("Command replicates exit command")

        with s:
            for i in range(10_000):
                try:
                    data = None
                    command = input('--> ')
                    if (command == ''): continue
                    if (command in exitcommands):
                        print("Terminated :)")
                        break
                    if (command == 'flush'):
                        s.reset_input_buffer()
                        continue
                    if (command.startswith('-')):
                        try: data = bytes.fromhex("".join(command[1:].split(' ')))
                        except ValueError: raise CommandError("Wrong hex command")
                    elif (command not in commands): raise CommandError("Wrong command")
                    if (not data): data = bytes.fromhex(cMsgs[command])
                    print(f"Data [{len(data)}]: {bytewise(data)}")
                    packet = wrap_pack(data+lrc(data), adr=12)
                    print(f"Packet [{len(packet)}]: {bytewise(packet)}")
                    s.write(packet)
                    time.sleep(0.05)
                    reply = s.read(s.in_waiting)
                    print(f"Reply packet [{len(reply)}]: {bytewise(reply)}")
                    replydata = unwrap(reply)
                    print(f"Reply data [{len(replydata[:-1])}]: {bytewise(replydata[:-1])}")
                    if (command in ('di', 'st',)):
                        print(f"String: '{replydata[1:-1].decode('utf-8')}'")
                    s.reset_input_buffer()
                except CommandError as e: print(e.args[0])
                except serial.serialutil.SerialTimeoutException as e: print(e.args[0])

    test_send_command()
    exit()
