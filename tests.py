import traceback
from itertools import count
import logging
from colored_logger import ColorHandler
import os
import sys
import pickle
import time

import math
import random
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

#TODO: application params (just globals for now)
COM = 'COM6'
ADR = 12
HEADER_LEN = 6              # in bytes
STARTBYTE = 0x5A         # type: int
MASTER_ADDRESS = 0          # should be in reply to host machine
samplepacket = b'Z\x0c\x06\x80\x9fs\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\x00\x0f\xcc'
samplereply = b'Z\x00\x05\x00\xa0\xff\x00\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\xcd\x10'


# 1           2     3:4           5:6         7:8       9:...         -3    -2:-1
# StartByte - ADR - Length|EVEN - HeaderRFC - COMMAND - CommandData - LRC - PacketRFC


log = logging.getLogger(__name__+":main")
log.setLevel(logging.DEBUG)
log.addHandler(ColorHandler())

slog = logging.getLogger(__name__+":serial")
slog.setLevel(logging.DEBUG)
slog.addHandler(ColorHandler())

SerialError = serial.serialutil.SerialException  # just an alias
SerialWriteTimeoutError = serial.serialutil.SerialTimeoutException  # just an alias
class SerialReadTimeoutError(SerialError): pass


class BadDataError(RuntimeError):
    """Data received is invalid or corrupted"""


def showError(e):
    log.error(f"{e.__class__.__name__}: {e.args[0] if e.args else '<No details>'}")


def showStackTrace(e):
    log.error(f"{e.__class__.__name__}: {e.args[0] if e.args else '<No details>'}")
    for line in traceback.format_tb(e.__traceback__):
        if (line): log.error(line.strip())

class SerialTransceiver(serial.Serial):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = COM
        self.baudrate = 921600
        self.write_timeout = 1
        self.timeout = 1


    def receivePacket(self):
        """
        Reads packet from serial datastream and returns unwrapped data:
            Reads header and determines the length of payload data
            Reads payload and wrapper footer (checksum - 2 bytes)
            Returns payload data if header and data lengths + header and packet checksums are OK. Raises error otherwise
        If header is not contained in very first bytes of datastream, sequentially reads bytes portions of header length
        until valid header is found. Raise error otherwise.
        No extra data is grabbed from datastream after valid packet is successfully read.

        :raises: SerialError, SerialReadTimeoutError, BadDataError, RuntimeError
        :return: unwrapped high-level data
        :rtype: bytes
        """

        bytesReceived = self.read(HEADER_LEN)

        if (len(bytesReceived) == HEADER_LEN and bytesReceived[0] == STARTBYTE and
                int.from_bytes(rfc1071(bytesReceived), byteorder='big') == 0):  #TODO: byteorder here and everywhere - ?
            header = bytesReceived
            return self.__readData(header)
        elif (len(bytesReceived) == 0):
            raise SerialReadTimeoutError("No reply")
        elif (len(bytesReceived) < HEADER_LEN):
            raise BadDataError(f"Bad packet (header too small, [{len(bytesReceived)}] out of [{HEADER_LEN}])")
        else:
            log.warning("Bad data in front of the stream. Searching for valid header...")
            for i in range(100):  #TODO: limit infinite loop in a better way
                while True:
                    startbyteIndex = bytesReceived.find(STARTBYTE)
                    if (startbyteIndex == -1):
                        if (len(bytesReceived) < HEADER_LEN):
                            raise BadDataError("Bad packet")
                        bytesReceived = self.read(HEADER_LEN)
                    else: break
                headerReminder = self.read(startbyteIndex)
                if (len(headerReminder) < startbyteIndex):
                    raise BadDataError("Bad packet")
                header = bytesReceived[startbyteIndex:] + headerReminder
                if (int.from_bytes(rfc1071(header), byteorder='big') == 0):
                    log.info("Found valid header")
                    return self.__readData(header)
            else: raise RuntimeError("Cannot find header in datastream, too many attempts...")


    def __readData(self, header):
        datalen, zerobyte = self.__parseHeader(header)
        data = self.read(datalen + 2)  # 2 is wrapper RFC
        if (len(data) < datalen + 2):
            raise BadDataError(f"Bad packet (data too small, [{len(data)}] out of [{datalen + 2}])")
        if (int.from_bytes(rfc1071(header + data), byteorder='big') == 0):
            slog.debug(f"Reply packet [{len(header+data)}]: {bytewise(header+data)}")
            return data[:-2] if (not zerobyte) else data[:-3]  # 2 is packet RFC, 1 is zero padding byte
        else:
            raise BadDataError(f"Bad packet checksum (expected '{bytewise(rfc1071(data[:-2]))}', "
                               f"got '{bytewise(data[-2:])}'). Packet discarded")


    @staticmethod
    def __parseHeader(header):
        assert (len(header) == HEADER_LEN)
        assert (header[0] == STARTBYTE)

        # unpack header (fixed structure - 6 bytes)
        fields = struct.unpack('< B B H H', header)
        if (fields[1] != MASTER_ADDRESS):
            raise BadDataError(f"Wrong master address (expected '{MASTER_ADDRESS}', got '{fields[1]}')")
        datalen = (fields[2] & 0x0FFF) * 2 # extract size in bytes, not 16-bit words
        zerobyte = (fields[2] & 1<<15) >> 15 # extract EVEN flag (b15 in LSB / b7 in MSB)
        # log.debug(f"ZeroByte: {zerobyte == 1}")
        return datalen, zerobyte


    def sendPacket(self, msg):
        """
        Wrap msg and send packet over serial port
        For DspAssist protocol - assumed that LRC byte is already appended to msg

        :param msg: binary payload data
        :type msg: bytes
        :return: bytes written count
        :rtype: int
        """

        datalen = len(msg)  # get data size in bytes
        assert (datalen <= 0xFFF)
        assert (ADR <= 0xFF)
        zerobyte = b'\x00' if (datalen % 2) else b''
        datalen += len(zerobyte)
        # below: data_size = datalen//2 ► translate data size in 16-bit words
        header = struct.pack('< B B H', STARTBYTE, ADR, (datalen//2) | (len(zerobyte) << 15))
        packet = header + rfc1071(header) + msg + zerobyte
        bytesSentCount = self.write(packet + rfc1071(packet))
        return bytesSentCount


def receivePacketBulk(com):
    """
    ### Function is not tested properly!
    Reads packet from serial datastream and returns unwrapped data:
        Reads header and determines the length of payload data
        Reads payload and wrapper footer (checksum - 2 bytes)
        Returns payload data if header and data lengths + header and packet checksums are OK. Raises error otherwise
    If header is not within very first bytes of datastream, reads all the data available and searches for packet there.
    All the data after valid packet found within taken sequence (if any) is lost!

    :param com: open serial object
    :type com: serial.Serial
    :return unwrapped high-level data
    :rtype bytes
    """

    bytesReceived = com.read(HEADER_LEN)
    headerOK = (len(bytesReceived) == HEADER_LEN and
                bytesReceived[0] == STARTBYTE and
                int.from_bytes(rfc1071(bytesReceived), byteorder='big') == 0
    ) #TODO: byteorder here and everywhere - ?
    if (headerOK):
        header = bytesReceived
        datalen, zerobyte = SerialTransceiver()._SerialTransceiver__parseHeader(header)
        data = com.read(datalen + 2) # 2 is wrapper RFC
        if (len(data) < datalen + 2):
            raise BadDataError(f"Bad packet (data too small, [{len(data)}] out of [{datalen + 2}])")
        if (int.from_bytes(rfc1071(header+data), byteorder='big') == 0):
            return data if (not zerobyte) else data[:-1]
        else:
            raise BadDataError(f"Bad packet checksum "
                               f"(expected '{bytewise(rfc1071(data[:-2]))}', got '{bytewise(data[-2:])}'). "
                               f"Packet discarded")
    elif (len(bytesReceived) == 0):
        raise SerialReadTimeoutError("No reply")
    elif (len(bytesReceived) < HEADER_LEN):
        raise BadDataError(f"Bad packet (header too small, [{len(bytesReceived)}] out of [{HEADER_LEN}])")
    else:
        log.info("Bad data in front of the stream. Searching for valid header...")
        for i in range(100): #TODO: limit infinite loop better (at least just raise a RuntimeError)
            bytesReceived += com.read(com.in_waiting or 1)  # 'or 1' is to let timeout occur if no data is on the stream
            if (len(bytesReceived) == 0):
                raise BadDataError("Bad packet (no data)")
            for idx in (i for (i, byte) in enumerate(bytesReceived) if byte == STARTBYTE):
                try:
                    header = bytesReceived[idx:idx + HEADER_LEN]
                except IndexError:  # that means we have reached the end of received data trying to get the header
                    break  # continue the upper loop (wait for more data)
                if (int.from_bytes(rfc1071(header), byteorder='big') == 0):
                    log.info("Found valid header")
                    datalen, zerobyte = SerialTransceiver()._SerialTransceiver__parseHeader(header)
                    reminderLen = datalen + 2 - (len(bytesReceived) - idx - HEADER_LEN)
                    data = com.read(reminderLen)
                    if (len(data) != reminderLen):
                        raise BadDataError(f"Bad packet (data too small, [{len(data)}] out of [{reminderLen}])")
                    if (int.from_bytes(rfc1071(header+data), byteorder='big') == 0):
                        if (bytesReceived): log.info("Unread data is left in the input buffer")
                        return data if (not zerobyte) else data[:-1]
                    else:
                        raise BadDataError(f"Bad packet checksum "
                                           f"(expected '{bytewise(rfc1071(data[:-2]))}', got '{bytewise(data[-2:])}'). "
                                           f"Packet discarded")
        else: raise RuntimeError("Cannot find header in datastream...")


    # analyse if smth is left in COM port buffer after all data is successfully received - ? how to do it right for now


class DspProtocol:

    # STRUCT CODES:
    # 1 byte (uint8)   -> B
    # 2 byte (uint16)  -> H
    # 4 byte (uint32)  -> I
    # 8 byte (uint64)  -> Q
    # float  (4 bytes) -> f
    # double (8 bytes) -> d
    # char[] (array)   -> s

    def __init__(self):
        self.tr = SerialTransceiver()

    # add to every method: method.required = bool() ► denotes command "obligatoriness"

    #TODO: write a decorator that will assign a method attrs (at least, 'required')
    # and pass inside an appropriate 'command' parameter taken from decorator parameter

    @staticmethod
    def __printReply(replydata):
        print(f"Reply [{len(replydata[:-1])}]: {bytewise(replydata[0])} - {bytewise(replydata[1:-1])}")


    def checkChannel(self, randomData=False):
        commandHexStr = '01 01'
        if(randomData):
            dataHexStr = struct.pack('< 8B', *(random.randrange(0, 0x100) for _ in range(8)))
        else:
            dataHexStr = '01 23 45 67 89 AB CD EF'
        self.tr.sendPacket(bytes.fromhex(commandHexStr + dataHexStr))
        reply = self.tr.receivePacket()
        if (lrc(reply)):
            raise BadDataError(f"Bad reply data checksum (expected '{bytewise(lrc(reply[:-1]))}', "
                                            f"got '{bytewise(reply[-1:])}'). Reply discarded")
        self.__printReply(reply)
        if (reply[1:9] != dataHexStr):
            raise BadDataError(f"Reply contains bad data (expected '{dataHexStr}', "
                               f"got '{bytewise(reply[1:9])}'). Reply discarded")
        return reply[0] == 0
    checkChannel.required = True

    def




# -------------------------------------------------------------------------------------------------------------------


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


def parseSignalDescriptor(data): # 6F 77 6C 56 6F 6C 74 61 67 65 00 00 07 08 00 00 00 FF FF 10 27 00 00 00 00 00 80 3F
    # assumes COMMAND is '03 02'
    sigName, fields = data.split(b'\0', 1)
    fields = struct.unpack('< B B ')
    ...


# -------------------------------------------------------------------------------------------------------------------


if __name__ == '__main__':

    def testDataLengthField(b_msg):
        dataLen = len(b_msg)  # 0x1000 - max number that fits into wrapper LENGTH field
        dataLenField = dataLen.to_bytes(2, 'little')

        checkDataLength = (dataLenField[1] & 0x0F) * 0x100 + dataLenField[0]
        print(checkDataLength, dataLen)


    def testCheckChannel():
        s = serial.Serial(port=COM, baudrate=921600,
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
        s = serial.Serial(port=COM, baudrate=921600,
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
        s = serial.Serial(port=COM, baudrate=921600,
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


    def test_bytes_receipt_speed():

        s = serial.Serial(port=COM, baudrate=921600,
                          bytesize=8, parity=serial.PARITY_NONE, stopbits=1,
                          write_timeout=1, timeout=1)

        with s:
            data = bytes.fromhex('0107' + 'DE'*369 + '00')
            packet = wrap_pack(data + lrc(data), adr=12)
            s.write(packet)
            prev = None
            for i in range(10_000):
                curr = s.in_waiting
                if (curr != prev):
                    print(curr)
                    prev = curr
            print(s.read(s.in_waiting))
            ...
        # Results:
        #       Packets are sent by pieces of 120 bytes length. They may group in multiples of 120.
        #       i.e. if packet is 380 bytes long, in_waiting amount of bytes in COM port input buffer may look like:
        #               (380)
        #               (120, 380)
        #               (240, 380)
        #               (120, 360, 380)
        #               ... and so on


    def test_double_read():
        s = serial.Serial(port=COM, baudrate=921600,
                          bytesize=8, parity=serial.PARITY_NONE, stopbits=1,
                          write_timeout=1, timeout=1)

        with s:
            data = bytes.fromhex('0101 AA BB CC DD EE FF 88 99')
            packet = wrap_pack(data + lrc(data), adr=12)
            s.write(packet)
            time.sleep(0.01)
            print(f"in_w before read 4 bytes: {s.in_waiting}")
            res = s.read(4)
            print("4 bytes received = " + bytewise(res))
            print(f"in_w after: {s.in_waiting}")
            time.sleep(0.01)
            try:
                res2 = s.read(s.in_waiting)
            except serial.serialutil.SerialTimeoutException:
                print("Timeout")
            else: print("Received all the rest: " + bytewise(res2))


    def test_send_command(testReceivePacket):
        class CommandError(RuntimeError): pass

        s = SerialTransceiver(port=COM, baudrate=921600, write_timeout=1, timeout=1)

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
            'tch-big': '0107' + 'AB'*349 + '00', # test channel (big amount of bytes)
            'sc': '03 01', # signals count
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
                    if (command == 'read'):
                        reply = s.read(s.in_waiting)
                        print(f"Reply packet [{len(reply)}]: {bytewise(reply)}") if (reply) else print("<Void>")
                        continue

                    if (command.startswith('sd')):
                        try: sigNum = int(command[2:], 16)
                        except ValueError: raise CommandError("Invalid signal number")
                        if (sigNum > 0xFFFF): raise CommandError("Signal number is too big")
                        data = bytes.fromhex(f'0302') + sigNum.to_bytes(2, 'little')
                    elif (command.startswith('-')):
                        try: data = bytes.fromhex("".join(command[1:].split(' ')))
                        except ValueError: raise CommandError("Wrong hex command")
                    elif (command not in commands): raise CommandError("Wrong command")
                    if (not data): data = bytes.fromhex(cMsgs[command])
                    slog.debug(f"Data [{len(data)}]: {bytewise(data[:2])} - {bytewise(data[2:])}")
                    if (testReceivePacket):
                        packet = wrap(data+lrc(data), adr=12)
                        s.sendPacket(data + lrc(data))
                    else:
                        packet = wrap(data+lrc(data), adr=12)
                        s.write(packet)
                    slog.debug(f"Packet [{len(packet)}]: {bytewise(packet)}")
                    if (testReceivePacket):
                        replydata = s.receivePacket()
                    else:
                        time.sleep(0.05)
                        reply = s.read(s.in_waiting)
                        replydata = unwrap(reply)
                        slog.debug(f"Reply packet [{len(reply)}]: {bytewise(reply)}")
                    slog.debug(f"Reply data [{len(replydata[:-1])}]: {bytewise(replydata[:1])} - {bytewise(replydata[1:-1])}")
                    if (command in ('di', 'st',)):
                        slog.debug(f"String: '{replydata[1:-1].decode('utf-8')}'")
                    s.reset_input_buffer()

                except CommandError as e: log.error(e.args[0])
                except serial.serialutil.SerialTimeoutException as e: showError(e)
                except BadDataError as e: showError(e)
                except SerialReadTimeoutError as e: showStackTrace(e)
                except RuntimeError as e: showError(e)


    def test_receivePacket():
        s = SerialTransceiver(port=COM, baudrate=921600, write_timeout=1, timeout=1)

        cMsgs = {
            'chch': '0101 AA BB CC DD EE FF 88 99',  # check channel
            'r': '0102',  # reset
            'di': '0103',  # device info
            'sm+': '010401',  # scan mode on
            'sm-': '010400',  # scan mode off
            # 'st': '0105',  # selftest
            'ss': '0106',  # save settings
            'tch': '0107 11 22 33 00',  # test channel
            # 'tch-0': '0107 11 22 33 44',  # test channel (without '0' ending)
            'tch-big': '0107' + 'AB' * 349 + '00',  # test channel (big amount of bytes)
            'sc': '03 01',  # signals count
        }

        with s:
            for c in cMsgs.values():
                data = bytes.fromhex(c)
                packet = wrap_pack(data + lrc(data), adr=12)
                print(f"Packet [{len(packet)}]: {bytewise(packet)}")
                s.write(packet)
                time.sleep(0.05)
                reply = s.receivePacket()
                print(f"Reply packet [{len(reply)}]: {bytewise(reply)}")
                input("pause...")
        print("[DONE]")

    functions = [
        lambda: ...,
        test_bytes_receipt_speed,
        test_double_read,
        test_send_command,
        test_receivePacket,
    ]

    functions[3](True)
