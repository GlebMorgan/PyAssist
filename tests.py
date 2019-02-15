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
from utils import bytewise, bitwise, legacy
from math import ceil
from enum import Enum

import bits
from functools import wraps


'''
(http://plaintexttools.github.io/plain-text-table)
'''

#TODO: application params (just globals for now)
COM = 'COM6'
ADR = 12
TIMEOUT = 0.5
HEADER_LEN = 6              # in bytes
STARTBYTE = 0x5A         # type: int
MASTER_ADDRESS = 0          # should be in reply to host machine

samplepacket = b'Z\x0c\x06\x80\x9fs\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\x00\x0f\xcc'
samplereply = b'Z\x00\x05\x00\xa0\xff\x00\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\xcd\x10'


# 1           2     3:4           5:6         7:8       9:...         -3    -2:-1
# StartByte - ADR - Length|EVEN - HeaderRFC - COMMAND - CommandData - LRC - PacketRFC


# slog - should be used for general serial communication info only (packets and timeouts)
slog = logging.getLogger(__name__+":serial")
slog.setLevel(logging.DEBUG)
slog.addHandler(ColorHandler())

#log - should be used for additional detailed info
log = logging.getLogger(__name__+":main")
log.setLevel(logging.DEBUG)
log.addHandler(ColorHandler())
log.disabled = False


ParseValueError = struct.error  # just an alias
SerialError = serial.serialutil.SerialException  # just an alias
SerialWriteTimeoutError = serial.serialutil.SerialTimeoutException  # just an alias
class SerialReadTimeoutError(SerialError): pass


class SerialCommunicationError(IOError):
    """Communication-level errors, indicate errors in packet transmission process"""

    def __init__(self, *args, data=None, dataname=None):
        if (data is not None):
            if (dataname is None):
                log.error(f"In call to {self.__class__} - 'dataname' attribute not specified")
                self.dataname = "Analyzed data"
            else: self.dataname = dataname
            self.data = data
        super().__init__(*args)


class BadDataError(SerialCommunicationError):
    """Data received over serial port is corrupted"""


class DeviceError(RuntimeError):
    """Application-level errors, indicate the command sent to the device was not properly executed"""


class BadAckError(SerialCommunicationError):
    """Devise has sent 'FF' acknowledge byte => error executing command on device side"""


class DataInvalidError(DeviceError):
    """Device reply contains invalid data"""


def showError(error):
    log.error(f"{error.__class__.__name__}: {error.args[0] if error.args else '<No details>'}" +
              (os.linesep + f"{error.dataname}: {bytewise(error.data)}" if hasattr(error, 'data') else ''))



def showStackTrace(e):
    log.error(f"{e.__class__.__name__}: {e.args[0] if e.args else '<No details>'}")
    for line in traceback.format_tb(e.__traceback__):
        if (line): log.error(line.strip())


class SerialTransceiver(serial.Serial):

    AUTO_LRC = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.port = COM
        self.baudrate = 921600
        self.write_timeout = TIMEOUT
        self.timeout = TIMEOUT


    class addCRC():
        """Decorator to sendPacket() method, appending LRC byte to msg"""

        def __init__(self, addLRC):
            self.addLRC = addLRC

        def __call__(self, sendPacketFunction):
            if (not self.addLRC):
                return sendPacketFunction
            else:
                @wraps(sendPacketFunction)
                def sendPacketWrapper(wrappee_self, msg, *args, **kwargs):
                    return sendPacketFunction(wrappee_self, msg+lrc(msg), *args, **kwargs)
                return sendPacketWrapper


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
            raise BadDataError(f"Bad header (too small, [{len(bytesReceived)}] out of [{HEADER_LEN}])",
                               dataname="Header", data=bytesReceived)
        else:
            if(bytesReceived[0] == STARTBYTE):
                log.warning(f"Bad header checksum (expected '{bytewise(rfc1071(bytesReceived[:-2]))}', "
                            f"got '{bytewise(bytesReceived[-2:])}'). Header discarded, searching for valid one...",
                            dataname="Header", data=bytesReceived)
            else:
                log.warning(f"Bad data in front of the stream: [{bytewise(bytesReceived)}]. "
                            f"Searching for valid header...")
            for i in range(1, 100):  #TODO: limit infinite loop in a better way
                while True:
                    startbyteIndex = bytesReceived.find(STARTBYTE)
                    if (startbyteIndex == -1):
                        if (len(bytesReceived) < HEADER_LEN):
                            raise BadDataError("Failed to find valid header")
                        bytesReceived = self.read(HEADER_LEN)
                        log.warning(f"Try next {HEADER_LEN} bytes: [{bytewise(bytesReceived)}]")
                    else: break
                headerReminder = self.read(startbyteIndex)
                if (len(headerReminder) < startbyteIndex):
                    raise BadDataError("Bad header", dataname="Header",
                                       data=bytesReceived[startbyteIndex:]+headerReminder)
                header = bytesReceived[startbyteIndex:] + headerReminder
                if (int.from_bytes(rfc1071(header), byteorder='big') == 0):
                    log.info(f"Found valid header at pos {i*HEADER_LEN+startbyteIndex}")
                    return self.__readData(header)
            else: raise RuntimeError("Cannot find header in datastream, too many attempts...")


    def __readData(self, header):
        datalen, zerobyte = self.__parseHeader(header)
        data = self.read(datalen + 2)  # 2 is wrapper RFC
        if (len(data) < datalen + 2):
            raise BadDataError(f"Bad packet (data too small, [{len(data)}] out of [{datalen + 2}])",
                               dataname="Packet", data=header+data)
        if (int.from_bytes(rfc1071(header + data), byteorder='big') == 0):
            slog.debug(f"Reply packet [{len(header+data)}]: {bytewise(header+data)}")
            if (self.in_waiting != 0):
                log.warning(f"Unread data ({self.in_waiting} bytes) is left in a serial datastream")
                self.reset_input_buffer()
                log.info(f"Serial input buffer flushed")
            return data[:-2] if (not zerobyte) else data[:-3]  # 2 is packet RFC, 1 is zero padding byte
        else:
            raise BadDataError(f"Bad packet checksum (expected '{bytewise(rfc1071(data[:-2]))}', "
                               f"got '{bytewise(data[-2:])}'). Packet discarded",
                               dataname="Packet", data=header+data)


    @staticmethod
    def __parseHeader(header):
        assert (len(header) == HEADER_LEN)
        assert (header[0] == STARTBYTE)

        # unpack header (fixed structure - 6 bytes)
        fields = struct.unpack('< B B H H', header)
        if (fields[1] != MASTER_ADDRESS):
            raise DataInvalidError(f"Wrong master address (expected '{MASTER_ADDRESS}', got '{fields[1]}')")
        datalen = (fields[2] & 0x0FFF) * 2 # extract size in bytes, not 16-bit words
        zerobyte = (fields[2] & 1<<15) >> 15 # extract EVEN flag (b15 in LSB / b7 in MSB)
        log.debug(f"ZeroByte: {zerobyte == 1}")
        return datalen, zerobyte


    @addCRC(AUTO_LRC)
    def sendPacket(self, msg):
        """
        Wrap msg and send packet over serial port
        For DspAssist protocol - if AUTO_LRC is False, it is assumed that LRC byte is already appended to msg

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
        packetToSend = packet + rfc1071(packet)
        bytesSentCount = self.write(packetToSend)
        slog.debug(f"Packet [{len(packetToSend)}]: {bytewise(packetToSend)}")
        return bytesSentCount


@legacy
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


# command wrapper
@legacy
def old_command_decorator(commandStrHex, required=False, type='UNSPECIFIED'):
    def command_wrapper(fun):
        from functools import wraps
        fun.command = commandStrHex
        @wraps(fun)
        def func_wrapper(*args, **kwargs):
            #TODO: get COMMANDS dict NOT from pulling it out of self.__class__ (that's ridiculous!)
            DspSerialApi.COMMANDS[fun.__name__] = commandStrHex
            return fun(*args, **kwargs)
        return func_wrapper
    return command_wrapper


class DspSerialApi:

    ACK_OK = 0x00
    ACK_BAD = 0xFF
    SELFTEST_TIMEOUT_SEC = 5
    TESTCHANNEL_DEFAULT_DATALEN = 1023
    TESTCHANNEL_DEFAULT_DATABYTE = 'AA'
    MAX_DATA_LEN_REPR = 25


    def __init__(self):
        self.tr = SerialTransceiver()


    class Command():
        """
        Command decorator
        Every command method returns execution result
        It may be a boolean value (in case no data is required from device) or data of appropriate type
        """

        class Type(Enum):
            NONE = 0
            UTIL = 1
            PROG = 2
            SIG = 3
            TELE = 4

        COMMANDS = {}

        def __init__(self, command, shortcut, required=False, category=Type.NONE):
            if (not isinstance(shortcut, str)): raise TypeError(f"'shortcut' must be a str, not {type(shortcut)}")
            try:
                if (len(bytes.fromhex(command)) != 2): raise ValueError
            except (ValueError, TypeError):
                raise TypeError("command' is not a valid 2 bytes hex string representation")

            self.shortcut = shortcut
            self.command = command
            self.required = required
            self.type = category


        def __call__(self, fun):
            @wraps(fun)
            def fun_wrapper(*args, **kwargs):
                args = (args[0], self.command) + args[1:]
                return fun(*args, **kwargs)

            fun_wrapper.command = self.command
            fun_wrapper.shortcut = self.shortcut
            fun_wrapper.required = self.required
            fun_wrapper.type = self.type
            self.COMMANDS[fun.__name__] = fun_wrapper
            return fun_wrapper


    @staticmethod
    def __printReply(replydata):
        if (isinstance(replydata, int)): slog.debug(f"Reply [1]: {hex(replydata)[2:].upper()} - {bytewise(b'')}")
        else: slog.debug(f"Reply [{len(replydata[:-1])}]: {bytewise(replydata[0:1])} - {bytewise(replydata[1:-1])}")


    def __sendCommand(self, data):
        """
        Add LRC byte to command data, send it to the device, receive reply packet,
            verify lrc and return ACK and reply payload data

        :param data: full command data
        :type data: bytes
        :return: 2-element tuple: ACK (boolean) and reply data (bytes), if any
        :rtype: tuple
        """

        self.tr.sendPacket(data+lrc(data))
        reply = self.tr.receivePacket()
        if (not reply):
            raise DataInvalidError("Empty reply")
        if (not lrc(reply)):
            raise BadDataError(f"Bad data checksum (expected '{bytewise(lrc(reply[:-1]))}', "
                               f"got '{bytewise(reply[-1:])}'). Reply discarded", data=reply)
        ACK = reply[0] == self.ACK_OK
        self.__printReply(reply)
        return ACK, reply[1:-1]


    @Command(command='01 01', shortcut='chch', required=True, category=Command.Type.UTIL)
    def checkChannel(self, command, data=None):
        """ API: checkChannel([data='XX XX ... XX'/'random']) """

        if (data == 'random'): checkingData = struct.pack('< 8B', *(random.randrange(0, 0x100) for _ in range(8)))
        elif (data is None): checkingData = bytes.fromhex('01 23 45 67 89 AB CD EF')
        else:
            if (len(data) != 8):
                raise ValueError("Data length should be 8 bytes")
            checkingData = bytes.fromhex(data)
        # 'command' may be referenced as 'self.checkChannel.command' instead of passing it here as a
        #  parameter (from decorator), but performance gain of that implementation is probably insignificant (?)
        ACK, reply = self.__sendCommand(bytes.fromhex(command) + checkingData)

        if (ACK and reply != checkingData):
            raise DataInvalidError(f"Reply contains bad data (expected [{bytewise(checkingData)}], "
                                   f"got [{bytewise(reply)}])")
        return ACK


    @Command(command='01 02', shortcut='r', required=False, category=Command.Type.UTIL)
    def reset(self, command):
        """ API: reset() """

        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (reply): raise DataInvalidError("Reply should contain no additional data")
        return ACK


    @Command(command='01 03', shortcut='i', required=True, category=Command.Type.UTIL)
    def deviceInfo(self, command):
        """ API: deviceInfo() """

        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (not reply): raise DataInvalidError("Empty data")
        #TODO: here ▼ and in selftest():
        # .decode may raise an 'utf-8 decode' error
        # redesign to trim the reply based on zero byte (b'\x00'), not null character ('\0') after data is decoded
        infoStr = reply.decode('utf-8').split('\0', 1)[0]
        return infoStr


    @Command(command='01 04', shortcut='sm', required=True, category=Command.Type.UTIL)
    def scanMode(self, command, enable):
        """API: scanMode('on'/'off') """

        if (enable is True or enable in ('on', 'ON', '+')): command += '01'
        elif (enable is False or enable in ('off', 'OFF', '-')): command += '00'
        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (reply): raise DataInvalidError("Reply should contain no additional data")
        return ACK


    @Command(command='01 05', shortcut='st', required=False, category=Command.Type.UTIL)
    def selftest(self, command):
        """ API: selftest() """

        initTimeout = self.tr.timeout
        self.tr.timeout = self.SELFTEST_TIMEOUT_SEC
        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (not reply): raise DataInvalidError("Empty data")
        selftestResultStr = reply.decode('utf-8').split('\0', 1)[0]
        self.tr.timeout = initTimeout
        return selftestResultStr


    @Command(command='01 06', shortcut='ss', required=False, category=Command.Type.UTIL)
    def saveSettings(self, command):
        """ API: saveSettings() """

        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (reply): raise DataInvalidError("Reply should contain no additional data")
        return ACK


    @Command(command='01 07', shortcut='tch', required=False, category=Command.Type.UTIL)
    def testChannel(self, command, data=None, N=None):
        """API: testChannel([data='XX XX ... XX'/'random', N=<data size in bytes> """

        if (N is None): N = self.TESTCHANNEL_DEFAULT_DATALEN
        elif (N > 1023): raise ValueError("Data length ('N') should be no more than 1023")
        if (data == 'random'):
            checkingData = struct.pack(f'< {N}B', *(random.randrange(0, 0x100) for _ in range(N)))
        elif (data is None):
            checkingData = bytes.fromhex(self.TESTCHANNEL_DEFAULT_DATABYTE * N)
        else:
            log.debug(f"Tch hex data: {data}")
            checkingData = bytes.fromhex(data[:N*2]) if N>0 else b''


        checkingData += b'\x00'
        ACK, reply = self.__sendCommand(bytes.fromhex(command) + checkingData)

        if (not ACK): return ACK
        if (reply != checkingData):
            raise DataInvalidError(f"Reply contains bad data ("
                                   f"expected [{bytewise(checkingData, collapseAfter=self.MAX_DATA_LEN_REPR)}], "
                                   f"got [{bytewise(reply, collapseAfter=self.MAX_DATA_LEN_REPR)}])")
        return ACK


    @Command(command='03 01', shortcut='sc', required=True, category=Command.Type.SIG)
    def signalsCount(self, command):
        """ API: signalsCount() """

        ACK, reply = self.__sendCommand(bytes.fromhex(command))

        if (not ACK): return ACK
        if (not reply): raise DataInvalidError("Empty data")
        try: nSignals = struct.unpack('< H', reply)[0]
        except ParseValueError: raise DataInvalidError("Cannot convert number of signals received to integer value")
        return nSignals

    @Command(command='03 02', shortcut='rsd', required=True, category=Command.Type.SIG)
    def readSignalsDescriptor(self, command, signal):
        """ API: readSignalsDescriptor(signal=<signal number>) """

        sigNumBytes = struct.pack('< H', signal)
        ACK, reply = self.__sendCommand(bytes.fromhex(command) + sigNumBytes)

        if (not ACK): return ACK
        if (not reply): raise DataInvalidError("Empty data")

        paramNames = ('Name', 'TypeClass', 'cType', 'Attrs', 'Parent', 'Period', 'Dimen', 'Factor')
        try:
            sigNameEndIndex = reply.index(b'\0')
            name = reply[:sigNameEndIndex].decode('utf-8')
            params = struct.unpack(
                    '< B B I h I B f', reply[sigNameEndIndex + 1:])
        except ValueError:
            raise DataInvalidError("Cannot parse signal descriptor field #1 - no null character found")
        except UnicodeDecodeError:
            raise DataInvalidError("Cannot parse signal descriptor field #1 - failed to convert data to utf-8 string")
        except ParseValueError:
            raise DataInvalidError("Failed to parse signal descriptor structure")

        params = (name,) + params

        paramNameMaxLen = max((len(par) for par in paramNames))
        # paramsMaxLen = max((len(str(par)) for par in params))
        log.info(f"Signal #{signal} descriptor parameters:")
        for name, par in zip(paramNames, params):
            if (name == 'Attrs'): par =  " ".join(f"{par:06b}")
            log.info(f"{name.rjust(paramNameMaxLen)} : {par}")

        return params






    # STRUCT CODES:
    # 1 byte (uint8)   -> B
    # 2 byte (uint16)  -> H
    # 4 byte (uint32)  -> I
    # 8 byte (uint64)  -> Q
    # float  (4 bytes) -> f
    # double (8 bytes) -> d
    # char[] (array)   -> s

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
                          write_timeout=TIMEOUT, timeout=TIMEOUT)

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
                          write_timeout=TIMEOUT, timeout=TIMEOUT)

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
                          write_timeout=TIMEOUT, timeout=5)
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
                          write_timeout=TIMEOUT, timeout=TIMEOUT)

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
                          write_timeout=TIMEOUT, timeout=TIMEOUT)

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

        s = SerialTransceiver(port=COM, baudrate=921600, write_timeout=TIMEOUT, timeout=TIMEOUT)

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

                except CommandError as e: log.error(e.args[0])
                except serial.serialutil.SerialTimeoutException as e: showError(e)
                except BadDataError as e: showError(e)
                except SerialReadTimeoutError as e: showStackTrace(e)
                except RuntimeError as e: showError(e)


    def test_receivePacket():
        s = SerialTransceiver(port=COM, baudrate=921600, write_timeout=TIMEOUT, timeout=TIMEOUT)

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

    def apiTest():
        assist = DspSerialApi()
        commands = {command.shortcut: command for command in assist.Command.COMMANDS.values()}
        class CommandError(RuntimeError): pass

        exitcommands = ('quit', 'exit', 'q', 'e')
        if (any(value in commands for value in exitcommands)):
            raise AttributeError("Command replicates exit command")

        with assist.tr as com:
            for i in range(10_000):
                try:
                    userinput = input('--> ')
                    command = userinput.split(' ', 1)[0]
                    if (command.strip() == ''): continue
                    elif (command in exitcommands):
                        print("Terminated :)")
                        break
                    elif (command == 'flush'):
                        com.reset_input_buffer()
                    elif (command == 'read'):
                        reply = com.read(com.in_waiting)
                        print(f"Reply packet [{len(reply)}]: {bytewise(reply)}") if (reply) else print("<Void>")
                    elif (command.startswith('-')):
                        try: data = bytes.fromhex("".join(command[1:].split(' ')))
                        except ValueError: raise CommandError("Wrong hex command")
                        slog.info(f"Data [{len(data)}]: {bytewise(data[:2])} - {bytewise(data[2:])}")
                        packet = wrap(data + lrc(data), adr=12)
                        com.sendPacket(data + lrc(data))
                        replydata = com.receivePacket()
                        slog.info(f"Reply data [{len(replydata[:-1])}]: "
                                   f"{bytewise(replydata[:1])} - {bytewise(replydata[1:-1])}")
                    elif (command.startswith('>')):
                        print(eval(userinput[1:]))
                    elif (not command in commands): raise CommandError("Wrong command")
                    else:
                        try:
                            print(commands[command](assist, *(eval(arg) for arg in userinput.split(' ')[1:])))
                        except TypeError as e:
                            if (f"{commands[command].__name__}()" in e.args[0]):
                                raise CommandError("Wrong arguments!" + os.linesep + e.args[0])
                            else: raise

                except CommandError as e: showError(e)
                except SerialCommunicationError as e: showError(e)
                except SerialError as e: showError(e)
                except DeviceError as e: showError(e)
                except Exception as e: showStackTrace(e)

    functions = [
        lambda: ...,
        test_bytes_receipt_speed,
        test_double_read,
        test_send_command,
        test_receivePacket,
        apiTest,
    ]

    functions[5]()
