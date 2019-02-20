import logging
import os
import re
import sys
import random
import string
import struct
import time
import traceback
from collections import namedtuple
from enum import Enum
from functools import wraps
from math import ceil

import bits
import progressbar
import serial
from autorepr import autorepr
from checksums import rfc1071, lrc
from timer import Timer
from utils import bytewise, bitwise, legacy

from colored_logger import ColorHandler


''' (http://plaintexttools.github.io/plain-text-table) '''


#TODO: application params (just globals for now)
COM = 'COM6'
ADR = 12
TIMEOUT = 0.5
HEADER_LEN = 6              # in bytes
STARTBYTE = 0x5A         # type: int
MASTER_ADDRESS = 0          # should be in reply to host machine


# COMMAND PACKET STRUCTURE
# 1           2     3:4           5:6         7:8       9:...         -3    -2:-1
# StartByte   ADR   Length|EVEN   HeaderRFC   COMMAND   CommandData   LRC   PacketRFC
#                                            [       command       ]

# REPLY PACKET STRUCTURE
# 1           2     3:4           5:6         7          10:...      -3    -2:-1
# StartByte   ADR   Length|EVEN   HeaderRFC   ACK byte   ReplyData   LRC   PacketRFC
#                                            [       reply        ]


# slog - should be used for general serial communication info only (packets and timeouts)
slog = logging.getLogger(__name__+":serial")
slog.setLevel(logging.WARNING)
slog.addHandler(ColorHandler())

#log - should be used for additional detailed info
log = logging.getLogger(__name__+":main")
log.setLevel(logging.INFO)
log.addHandler(ColorHandler())
log.disabled = False


ParseValueError = struct.error  # just an alias
SerialError = serial.serialutil.SerialException  # just an alias
SerialWriteTimeoutError = serial.serialutil.SerialTimeoutException  # just an alias
class SerialReadTimeoutError(SerialError): pass


class SerialCommunicationError(IOError):
    """Communication-level error, indicate failure in packet transmission process"""

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


class BadRfcError(SerialCommunicationError):
    """RFC chechsum validation failed"""


class BadLrcError(SerialCommunicationError):
    """LRC chechsum validation failed"""


class BadAckError(SerialCommunicationError):
    """Devise has sent 'FF' acknowledge byte => error executing command on device side"""


class DeviceError(RuntimeError):
    """Firmware-level error, indicate the command sent to the device was not properly executed"""


class DataInvalidError(DeviceError):
    """Device reply contains invalid data"""


class CommandError(RuntimeError):
    """Application-level error, indicates invalid command signature / parameters / semantics"""


def showError(error):
    log.error(f"{error.__class__.__name__}: {error.args[0] if error.args else '<No details>'}" +
              (os.linesep + f"{error.dataname}: {bytewise(error.data)}" if hasattr(error, 'data') else ''))



def showStackTrace(e):
    log.error(f"{e.__class__.__name__}: {e.args[0] if e.args else '<No details>'}")
    for line in traceback.format_tb(e.__traceback__):
        if (line): log.error(line.strip())


class SerialTransceiver(serial.Serial):

    AUTO_LRC = False
    RFC_CHECK_DISABLED = True
    LRC_CHECK_DISABLED = False

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

        # TODO: byteorder here ▼ and everywhere - ?
        if (len(bytesReceived) == HEADER_LEN and bytesReceived[0] == STARTBYTE and
                (self.RFC_CHECK_DISABLED or int.from_bytes(rfc1071(bytesReceived), byteorder='big') == 0)):
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
                if (self.RFC_CHECK_DISABLED or int.from_bytes(rfc1071(header), byteorder='big') == 0):
                    log.info(f"Found valid header at pos {i*HEADER_LEN+startbyteIndex}")
                    return self.__readData(header)
            else: raise SerialCommunicationError("Cannot find header in datastream, too many attempts...")
        #TODO: still have unread data at the end of the serial stream sometimes.
        # scenario that once caused the issue: send 'ms 43 0' without adding a signal value (need to alter the code)


    def __readData(self, header):
        datalen, zerobyte = self.__parseHeader(header)
        data = self.read(datalen + 2)  # 2 is wrapper RFC
        if (len(data) < datalen + 2):
            raise BadDataError(f"Bad packet (data too small, [{len(data)}] out of [{datalen + 2}])",
                               dataname="Packet", data=header+data)
        if (self.RFC_CHECK_DISABLED or int.from_bytes(rfc1071(header + data), byteorder='big') == 0):
            slog.debug(f"Reply packet [{len(header+data)}]: {bytewise(header+data)}")
            if (self.in_waiting != 0):
                log.warning(f"Unread data ({self.in_waiting} bytes) is left in a serial datastream")
                self.reset_input_buffer()
                log.info(f"Serial input buffer flushed")
            return data[:-2] if (not zerobyte) else data[:-3]  # 2 is packet RFC, 1 is zero padding byte
        else:
            raise BadRfcError(f"Bad packet checksum (expected '{bytewise(rfc1071(data[:-2]))}', "
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
            raise BadRfcError(f"Bad packet checksum "
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
                        raise BadRfcError(f"Bad packet checksum "
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

    #TODO: on upper layer: if command returns bad ACK, first check
    # whether all conditions, described in DSP protocol, were met

    #TODO: correct and unify all error-messages:
    # "Error cause (type/value mismatch, invalid data, whatever): required {proper}, got {actual}"

    #TODO: add to every bytewise() call 'collapseAfter=self.MAX_DATA_LEN_REPR' argument if long data output is possible

    # STRUCT CODES:
    # 1 byte (uint8)   -> B
    # 2 byte (uint16)  -> H
    # 4 byte (uint32)  -> I
    # 8 byte (uint64)  -> Q
    # float  (4 bytes) -> f
    # double (8 bytes) -> d
    # char[] (array)   -> s

    ACK_OK = 0x00
    ACK_BAD = 0xFF
    SELFTEST_TIMEOUT_SEC = 5
    TESTCHANNEL_DEFAULT_DATALEN = 1023
    TESTCHANNEL_DEFAULT_DATABYTE = 'AA'
    MAX_DATA_LEN_REPR = 25


    def __init__(self):
        self.tr = SerialTransceiver()

    class Signal():
        #TODO: redesign all the class using (possibly) named tuples
        # (or anything that is efficient and readable

        #TODO: redesign wherever necessary to replace all pre-checks (typically, involving 'if's) to try-except blocks
        # examples:
        # ——— check 'signal' parameter (whether it's 'Signal()' or 'int') -> get attribute signal.n and try-exept it
        # ——— instead of checking ACK and whether the command should return any data, add respective command method attr
        # leave only those checks when wrong values can cause device-side error or misoperation

        # these are Signal() attributes after object initialization ▼

        paramNames = ('Name', 'Class', 'Type', 'Attrs', 'Parent', 'Period', 'Dimen', 'Factor')

        attrsNames = ('control', 'node', 'signature', 'read', 'setting', 'telemetry')
        paramNamesMaxLen = max((len(par) for par in paramNames))
        attrNamesMaxLen = max((len(attr) for attr in attrsNames))

        # paramsMaxLen = max((len(str(par)) for par in params))

        Class = {
            0: 'VAR',
            1: 'ARRAY',
            2: 'MATRIX',
        }

        Type = {
            0: 'string',
            1: 'bool',
            2: 'byte',
            3: 'uint',
            4: 'int',
            5: 'long',
            6: 'ulong',
            7: 'float',
        }

        structTypeCode = {
            0: NotImplemented,
            1: 'B',   # uint_8  -> 1 byte
            2: 'B',   # uint_8  -> 1 byte
            3: 'H',   # uint_16 -> 2 bytes
            4: 'h',    # int_16  -> 2 bytes
            5: 'i',   # int_32  -> 4 bytes
            6: 'I',  # uint_32 -> 4 bytes
            7: 'f',  # float   -> 4 bytes
        }

        Dimen = {
            0: '',
            1: 'V',
            2: 'A',
            3: '°',
            4: 'rad',
            5: 'm',
            6: 'V/°C',
            7: 'm/s',
            8: '°C',
            9: '°C/s',
        }


        def __init__(self, sigNum=None, params=None, **kwargs):
            #TODO: add 'nChildren' field for node signals (for non nodes that could be 'None' or just '0')
            if (sigNum is not None and params is not None):
                if (not hasattr(params, '__iter__')):
                    raise TypeError("'params' should be an iterable containing descriptor parameters")
                if (len(params) != len(self.paramNames)):
                    raise TypeError("Wrong number of parameters")
                self.n = sigNum
                for name, par in zip(self.paramNames, params): setattr(self, name.lower(), par)
            elif (kwargs):
                for name, par in kwargs:
                    try:
                        setattr(self, name.lower(), par)
                    except TypeError: raise ValueError(f"Parameter {name}={par} is not valid signal object attribute")
            else: raise TypeError(f"[Signal number + parameters iterable] OR [all parameters as keywords] signature "
                                  f"expected in call to {self.__class__.__name__}()")


        __repr__ = autorepr("{self.name} <{self.Signal.Type[self.type]}>")


        def showSigDescriptor(self):
            descriptorStrLines = [f"Signal #{self.n} descriptor:"]
            for name in self.paramNames:
                par = getattr(self, name.lower())
                if (name == 'Attrs'):
                    # attrs as flags sequence ▼
                    descriptorStrLines.append(f"""{name.rjust(self.paramNamesMaxLen)} : {" ".join(f"{par:06b}")}""")
                    # attrs as list (parsed) ▼
                    for nAttr, attrName in enumerate(self.attrsNames):
                        descriptorStrLines.append(f"{attrName.rjust(self.paramNamesMaxLen + self.attrNamesMaxLen)} = "
                                 f"{bits.flag(par, nAttr)}")
                    continue
                if (hasattr(self, name) and isinstance(getattr(self, name), dict)):
                    par = getattr(self, name)[par] or '<None>'
                descriptorStrLines.append(f"{name.rjust(self.paramNamesMaxLen)} : {par}")
            return os.linesep.join(descriptorStrLines)


        def __str__(self):
            attrsList = ', '.join(
                    (attrName for nAttr, attrName in enumerate(self.attrsNames) if bits.flag(self.attrs, nAttr))
            )
            return f"Signal #{self.n} - {self.name} <{self.Type[self.type]}>, " \
                   f"attrs=({attrsList}), parent={self.parent}"


    class Command():
        """
        Command decorator

        Every command method returns execution result (data or ACK)
        ACK is a boolean value (returned in case no data is required from device), data is of its own appropriate type
        Reply data presence is not checked at decorator level
            (that also means if reply contains extra (unnecessary) data, it will be ignored)
        """

        # map [full command method names] to [command methods themselves] ▼
        COMMANDS = {}

        class Type(Enum):
            NONE = 0
            UTIL = 1
            PROG = 2
            SIG = 3
            TELE = 4

        def __init__(self, command, shortcut, required=False, category=Type.NONE):
            if (not isinstance(shortcut, str)):
                raise TypeError(f"'shortcut' must be a str, not {type(shortcut)}")
            try:
                if (len(bytes.fromhex(command)) != 2): raise ValueError
            except (ValueError, TypeError):
                raise ValueError(f"'command' should be a valid 2 bytes hex string representation, not {command}")
            if (not isinstance(category, self.Type)):
                raise TypeError(f"'category' should be of {self.Type.__class__} type, not {category.__class__}")

            self.shortcut = shortcut
            self.command = command
            self.required = bool(required)
            self.type = category


        def __call__(self, fun):
            @wraps(fun)
            def fun_wrapper(*args, **kwargs):
                args = (args[0], self.command) + args[1:]
                log.info("Command: " +
                         re.sub(r'((?<=[a-z])[A-Z]|(?<!\A)[A-Z](?=[a-z]))', r' \1', fun.__name__).capitalize())
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
            verify lrc and return reply payload data (or raise 'BadAckError' if bad ACK is received)

        :param data: full command data
        :type data: bytes
        :return: 2-element tuple: ACK (boolean) and reply data (bytes), if any
        :rtype: tuple
        """

        self.tr.sendPacket(data+lrc(data))
        reply = self.tr.receivePacket()

        if (len(reply) < 2): raise DataInvalidError("Empty reply")
        if (not lrc(reply)):
            raise BadLrcError(f"Bad data checksum (expected '{bytewise(lrc(reply[:-1]))}', "
                               f"got '{bytewise(reply[-1:])}'). Reply discarded", dataname="Reply", data=reply)
        if (reply[0] != self.ACK_OK):
            raise BadAckError(f"Command execution failed", dataname="Reply", data=reply)

        self.__printReply(reply)
        return reply[1:-1]


    def getCommandApi(self, commandMethod):
        try: commandDocstring = commandMethod.__doc__
        except KeyError: raise AttributeError(f"Command method not found in {self.__class__.__name__} command API")
        if (commandDocstring is None): return '<Not found>'
        try:
            methodNameStartIndex = commandDocstring.index('API: ') + 5
        except ValueError:
            raise ValueError(f"Cannot find API siganture in {commandMethod.__name__} method docstring")
        methodName = commandMethod.__name__
        bracketsLevel = 0
        for pos, char in enumerate(commandDocstring[methodNameStartIndex:], start=methodNameStartIndex):
            if (char == '('):
                if (bracketsLevel == 0):
                    openBracketIndex = pos

                    apiName = commandDocstring[methodNameStartIndex:openBracketIndex]
                    if (not frozenset(apiName).issubset(frozenset(string.ascii_letters + '_'))):
                        raise ValueError(f"Invalid API singature method name '{apiName}'")
                    if (apiName != methodName):
                        raise ValueError(f"API signature method name '{apiName}' "
                                         f"does not match actual command method name '{methodName}'")
                bracketsLevel += 1
            elif (char == ')'):
                bracketsLevel -= 1
                if (bracketsLevel == 0):
                    closeBracketIndex = pos
                    break
        try: return commandDocstring[methodNameStartIndex:closeBracketIndex+1]
        except NameError: return f"{methodName}: {commandDocstring[methodNameStartIndex:]}"


    """
    DocString command method API micro-syntax:
    
    (_, _, ..., _) - method parameters
    [...]          - optional parameter
    .../...        - variations of parameter type
    ...|...        - variations of parameter value
    <...>          - lexeme grouping (just like usual parenthesis
    ...            - arbitrary number of elements
    
    """


    @Command(command='01 01', shortcut='chch', required=True, category=Command.Type.UTIL)
    def checkChannel(self, command, data=None):
        """ API: checkChannel([data='XX XX ... XX'/'random']) """

        if (data == 'random'): checkingData = struct.pack('< 8B', *(random.randrange(0, 0x100) for _ in range(8)))
        elif (data is None): checkingData = bytes.fromhex('01 23 45 67 89 AB CD EF')
        else:
            if (len(data) != 8): raise CommandError("Data length should be 8 bytes")
            checkingData = bytes.fromhex(data)

        # 'command' may be referenced as 'self.checkChannel.command' instead of passing it here as a
        #  parameter (from decorator), but performance gain of that implementation is probably insignificant (?)
        reply = self.__sendCommand(bytes.fromhex(command) + checkingData)

        if (reply != checkingData):
            raise DataInvalidError(f"Reply contains bad data (expected [{bytewise(checkingData)}], "
                                   f"got [{bytewise(reply)}])")
        return bytewise(reply)


    @Command(command='01 02', shortcut='r', required=False, category=Command.Type.UTIL)
    def reset(self, command):
        """ API: reset() """

        self.__sendCommand(bytes.fromhex(command))


    @Command(command='01 03', shortcut='i', required=True, category=Command.Type.UTIL)
    def deviceInfo(self, command):
        """ API: deviceInfo() """

        reply = self.__sendCommand(bytes.fromhex(command))

        #TODO: here ▼ and in selftest():
        # .decode may raise an 'utf-8 decode' error
        # redesign to trim the reply based on zero byte (b'\x00'), not null character ('\0') after data is decoded
        try: infoStr = reply.decode('utf-8').split('\0', 1)[0]
        except: raise
        return infoStr


    @Command(command='01 04', shortcut='sm', required=True, category=Command.Type.UTIL)
    def scanMode(self, command, enable):
        """API: scanMode('on'/'off') """

        if (enable is True or enable in ('on', 'ON', '+')): mode = '01'
        elif (enable is False or enable in ('off', 'OFF', '-')): mode = '00'
        else: raise CommandError(f"Invalid mode: expected ['on'/'off'], got {enable}")
        reply = self.__sendCommand(bytes.fromhex(command + mode))


    @Command(command='01 05', shortcut='st', required=False, category=Command.Type.UTIL)
    def selftest(self, command):
        """ API: selftest() """

        initTimeout = self.tr.timeout
        self.tr.timeout = self.SELFTEST_TIMEOUT_SEC

        reply = self.__sendCommand(bytes.fromhex(command))

        try: selftestResultStr = reply.decode('utf-8').split('\0', 1)[0]
        except: raise

        self.tr.timeout = initTimeout
        return selftestResultStr


    @Command(command='01 06', shortcut='ss', required=False, category=Command.Type.UTIL)
    def saveSettings(self, command):
        """ API: saveSettings() """

        self.__sendCommand(bytes.fromhex(command))


    @Command(command='01 07', shortcut='tch', required=False, category=Command.Type.UTIL)
    def testChannel(self, command, data=None, N=None):
        """API: testChannel([data='XX XX ... XX'/'random', N=<data size in bytes>) """

        if (N is None): N = self.TESTCHANNEL_DEFAULT_DATALEN
        elif (N > 1023): raise CommandError("Data length ('N') should be no more than 1023")
        if (data == 'random'):
            checkingData = struct.pack(f'< {N}B', *(random.randrange(0, 0x100) for _ in range(N)))
        elif (data is None):
            checkingData = bytes.fromhex(self.TESTCHANNEL_DEFAULT_DATABYTE * N)
        else:
            log.debug(f"Tch hex data: {data}")
            checkingData = bytes.fromhex(data[:N*2]) if N>0 else b''

        checkingData += b'\x00'
        reply = self.__sendCommand(bytes.fromhex(command) + checkingData)

        if (reply != checkingData):
            raise DataInvalidError(f"Reply contains bad data ("
                                   f"expected [{bytewise(checkingData, collapseAfter=self.MAX_DATA_LEN_REPR)}], "
                                   f"got [{bytewise(reply, collapseAfter=self.MAX_DATA_LEN_REPR)}])")
        return bytewise(reply, collapseAfter=self.MAX_DATA_LEN_REPR)


    @Command(command='03 01', shortcut='sc', required=True, category=Command.Type.SIG)
    def signalsCount(self, command):
        """ API: signalsCount() """

        reply = self.__sendCommand(bytes.fromhex(command))

        if (not reply): raise DataInvalidError("Empty data")
        try: nSignals = struct.unpack('< H', reply)[0]
        except ParseValueError: raise DataInvalidError(f"Cannot convert data to integer value: [{reply}]")
        return nSignals


    @Command(command='03 02', shortcut='rsd', required=True, category=Command.Type.SIG)
    def readSignalDescriptor(self, command, signalNum):
        """ API: readSignalDescriptor(signalNum=<signalNum number>) """

        reply = self.__sendCommand(bytes.fromhex(command) + struct.pack('< H', signalNum))

        if (not reply): raise DataInvalidError("Empty data")
        try:
            sigNameEndIndex = reply.find(b'\0')
        except ValueError:
            raise DataInvalidError(f"Cannot parse descriptor #{signalNum} field #1 - no null character found")
        try:
            name = reply[:sigNameEndIndex].decode('utf-8')
        except UnicodeDecodeError:
            raise DataInvalidError(f"Cannot parse descriptor #{signalNum} field #1 - "
                                   f"failed to convert data to utf-8 string")
        try:
            params = struct.unpack('< B B I h I B f', reply[sigNameEndIndex + 1:])
        except ParseValueError:
            if (int.from_bytes(reply[sigNameEndIndex + 1], byteorder='little') > 0):
                raise NotImplementedError("Complex type class signals are not supported")
            raise DataInvalidError(f"Failed to parse descriptor #{signalNum} structure: "
                                   f"[{bytewise(reply[sigNameEndIndex + 1:])}]")

        params = (name,) + params
        signal = self.Signal(signalNum, params)
        log.info(signal.showSigDescriptor())
        return signal


    @Command(command='03 03', shortcut='ms', required=False, category=Command.Type.SIG)
    def manageSignal(self, command, signal, mode, value=None):
        """ API: manageSignal(signal=Signal()/<signal number>, mode=<0|1|2>/<none|fix|sign>, [value=<signal value>]')
        if method is called with no signal value, it just changes signal mode without changing signal value """

        # check 'mode' argument
        #TODO: move 'modes' definition to self.Signal() ▼
        modes = ('none', 'fix', 'sign')
        if (isinstance(mode, str)):
            try: mode = modes.index(mode)
            except ValueError:
                raise CommandError(f"Mode '{mode}' is invalid. "
                                 f"""Should be within ({', '.join(f"'{s}'" for s in modes)})""")
        if (mode == 2): raise NotImplementedError("Signature control mode is not supported")
        elif (mode > 2): raise CommandError(f"Mode {mode} is invalid. Should be within [0..{len(modes)-1}]")

        # check 'signal' argument
        if (isinstance(signal, int)):
            signal = self.readSignalDescriptor(signal)
        elif (not isinstance(signal, self.Signal)):
            raise CommandError("'signal' argument type is invalid. Should be either 'Signal()' or 'int'")

        #check 'value' argument
        if (value is None): value = self.readSignal(signal)

        # pack and send command
        commandParams = struct.pack('< H B', signal.n, mode)
        if (self.Signal.Type[signal.type] == 'string'):
            raise NotImplementedError(f"Cannot assign to string-type signal "
                                "(for what on Earth reason do you wanna do that???)")
        try: commandValue = struct.pack(f'< {self.Signal.structTypeCode[signal.type]}', value)
        except ParseValueError: raise ValueError(f"Cannot assign '{value}' to '{signal.name}' signal")
        # log.debug(f"Signal number and mode - {signal.n}, {mode}")
        # log.debug(f"Packed - {bytewise(commandParams)}")
        # log.debug(f"Signal value - {value}")
        # log.debug(f"Packed - {bytewise(commandValue)}")

        reply = self.__sendCommand(bytes.fromhex(command) + commandParams + commandValue)


    @Command(command='03 04', shortcut='ssg', required=False, category=Command.Type.SIG)
    def setSignature(self, command, *args):
        """ API: NotImplemented"""
        return NotImplemented


    @Command(command='03 05', shortcut='rs', required=False, category=Command.Type.SIG)
    def readSignal(self, command, signal):
        """ API: readSignal(signal=Signal()/<signal number>) """

        if (isinstance(signal, int)):
            signal = self.readSignalDescriptor(signal)
        elif (not isinstance(signal, self.Signal)):
            raise CommandError("'signal' argument type is invalid. Should be either 'Signal()' or 'int'")

        reply = self.__sendCommand(bytes.fromhex(command) + struct.pack('< H', signal.n))

        if (not reply): return None
        #TODO: add functionality to read string-type signals! ▼
        try: sigVal = struct.unpack(f'< {self.Signal.structTypeCode[signal.type]}', reply)[0]
        except ParseValueError: raise DataInvalidError(f"Failed to parse '{signal.name}' signal value: "
                                   f"[{bytewise(reply)}]")
        return sigVal


    @Command(command='04 01', shortcut='rtd', required=True, category=Command.Type.TELE)
    def readTelemetryDescriptor(self, command):
        """ API: readTelemetryDescriptor() """

        reply = self.__sendCommand(bytes.fromhex(command))

        if (not reply): raise DataInvalidError("Empty data")
        try: params = struct.unpack('< I H H I', reply)
        except ParseValueError:
            raise DataInvalidError(f"Failed to parse telemetry descriptor structure: [{bytewise(reply)}]")
        if (bits.flag(params[3], 0) == 1): raise NotImplementedError("Stream transmission mode is not supported")
        if (bits.flag(params[3], 1) == 1): raise NotImplementedError("Data framing is not supported")

        #TODO: move logging to self.Telemetry.showTeleDescriptor() ▼
        paramNames = ('Period', 'SignalsCount', 'FrameSize', 'Attrs')
        paramNamesMaxWidth = max(len(name) for name in paramNames)
        log.info(f"Telemetry descriptor:")
        for parNum, parName in enumerate(paramNames):
            comment = ""
            if(parName == 'Attrs'):
                # attrs as flags sequence ▼
                log.info(f"""{parName.rjust(paramNamesMaxWidth)} : {" ".join(f"{params[parNum]:03b}")}""")
                # attrs as list (parsed) ▼
                for nAttr, attrName in enumerate(("Streaming", "Framing", "Buffering")):
                    log.info(f"{attrName.rjust(paramNamesMaxWidth+9)} = "
                             f"{bits.flag(params[3], nAttr)}")
                continue
            if (parName == 'Period'): comment = f" ({1/(params[parNum]/100/1_000_000)} Hz)"
            log.info(f"{parName.rjust(paramNamesMaxWidth)} : {params[parNum]}{comment}")

        #TODO: return self.Telemetry() object instead ▼
        return {parName: par for parName, par in zip(paramNames, params)}


    @Command(command='04 02', shortcut='tm', required=True, category=Command.Type.TELE)
    def setTelemetry(self, command, mode, periodCoef=5, dataframeSize=0):
        """ API: TODO"""

        self.Telemetry = namedtuple('telemetryStub', 'Period FrameSize')(10000, 0)  # ◄ stub - TODO: add Telemetry subclass

        # check 'mode' argument
        modes = ('reset', 'stream', 'framewise', 'buffered', 'stop') #TODO: add 'start' mode as an alias to 'buffered'
        if (isinstance(mode, int)):
            if (mode > len(modes)-1):
                raise CommandError(f"Mode '{mode}' is invalid. Should be within [0..{len(modes)-1}]")
        else:
            try: mode = modes.index(mode)
            except ValueError:
                raise CommandError(f"Mode '{mode}' is invalid. "
                                   f"""Should be within ({', '.join(f"'{s}'" for s in modes)})""")

        # check 'periodCoef' argument
        if (not isinstance(periodCoef, int) or periodCoef < 0 or periodCoef > self.Telemetry.Period):
            raise CommandError(f"Period coefficient should be reasonable positive integer value, not {periodCoef}")

        # check 'dataframeSize' argument
        if (not isinstance(dataframeSize, int) or dataframeSize < 0 or dataframeSize > self.Telemetry.FrameSize):
            raise CommandError(f"Dataframe size should be reasonable positive integer value, not {periodCoef}")

        commandParams = struct.pack('< B I H', mode, periodCoef, dataframeSize)

        self.__sendCommand(bytes.fromhex(command) + commandParams)


    @Command(command='04 03', shortcut='as', required=True, category=Command.Type.TELE)
    def addSignal(self, command, signal):
        """ API: addSignal(signal=Signal()/<signal number>) """

        #TODO: this ▼ code block repeats frequently. If won't be removed, extract method
        # detect all-the-rest code repetitions and extract internal methods for them
        if (isinstance(signal, int)):
            signal = self.readSignalDescriptor(signal)
        elif (not isinstance(signal, self.Signal)):
            raise CommandError("'signal' argument type is invalid. Should be either 'Signal()' or 'int'")

        self.__sendCommand(bytes.fromhex(command) + struct.pack('< H', signal.n))


    @Command(command='04 04', shortcut='rt', required=True, category=Command.Type.TELE)
    def readTelemetry(self, command):
        """ API: TODO """

        reply = self.__sendCommand(bytes.fromhex(command))
        if (not reply): raise DataInvalidError("Empty data") #TODO: what to do if reply is empty? ...

        print(bytewise(reply))

        return NotImplemented










    def scanSignals(self, attempts=2, showProgress=False):
        nSignals = self.signalsCount()
        signalDescriptors = []
        failedSignalIndices = []
        if (showProgress):
            progressbarElements = (
                progressbar.widgets.Bar(marker='█', left='', right='', fill='░'), ' ', progressbar.Percentage()
            )
            progress = progressbar.ProgressBar(widgets=progressbarElements, fd=sys.stdout)
        else: progress = iter
        for signalNum in progress(range(nSignals)):
            for _ in range(attempts):
                currSignal = self.readSignalDescriptor(signalNum)
                if (currSignal):
                    signalDescriptors.append(currSignal)
                    break
            else: failedSignalIndices.append(signalNum)
        return tuple(signalDescriptors), tuple(failedSignalIndices)


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
        samplepacket = b'Z\x0c\x06\x80\x9fs\x01\x01\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\x00\x0f\xcc'
        samplereply = b'Z\x00\x05\x00\xa0\xff\x00\xaa\xbb\xcc\xdd\xee\xff\x88\x99\x00\xcd\x10'
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

        def __showHelp(inputParameters):
            try: requestApiCommand = inputParameters.split(maxsplit=1)[1]
            except IndexError:
                # command is just "help" → show all commands signatures
                print("Commands API:")
                for apiCommandMethod in assist.Command.COMMANDS.values():
                    print(f"{apiCommandMethod.shortcut:>5} - {assist.getCommandApi(apiCommandMethod)}")
            else:
                # command contains explicit API command → show signature of requested command only
                if (requestApiCommand in (fun.__name__ for fun in assist.Command.COMMANDS.values())):
                    # requested API command is a full command method name
                    print(f"API: {assist.getCommandApi(assist.Command.COMMANDS[requestApiCommand])}")
                elif (requestApiCommand in (fun.shortcut for fun in assist.Command.COMMANDS.values())):
                    # requested API command is a shortcut
                    print(f"API: {assist.getCommandApi(commands[requestApiCommand])}")
                else:
                    # requested API command is invalid
                    raise CommandError(f"Cannot find API method name / shortcut '{requestApiCommand}'")

        assist = DspSerialApi()

        # map [API method shortcuts] to [method objects themselves] ▼
        commands = {command.shortcut: command for command in assist.Command.COMMANDS.values()}

        exitcommands = ('quit', 'exit', 'q', 'e')
        reservedcommands = ('help', 'h', 'read', 'flush')
        if (any(value in commands for value in exitcommands + reservedcommands)):
            raise AssertionError("One ore more API commands duplicate reserved command")

        with assist.tr as com:
            for i in range(10_000):
                try:
                    userinput = input('--> ')
                    if (userinput.strip() == ''): continue

                    command = userinput.strip().split(maxsplit=1)[0]

                    if (command in exitcommands):
                        print("Terminated :)")
                        break

                    elif (command == 'help' or command == 'h'):
                        __showHelp(userinput)

                    elif (command == 'flush'):
                        com.reset_input_buffer()

                    elif (command == 'read'):
                        reply = com.read(com.in_waiting)
                        print(f"Reply packet [{len(reply)}]: {bytewise(reply)}") if (reply) else print("<Void>")

                    elif (command == 'scans'):
                        with Timer("scan signals"):
                            signals, failedSignals = assist.scanSignals()
                        if (failedSignals):
                            log.warning(f"{len(failedSignals)} signals failed to scan: "
                                        f"{tuple(sigNum for sigNum in failedSignals)}")
                        print(tuple(sig.name for sig in signals))

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
                        print(exec(userinput[1:].strip()))

                    elif (not command in commands): raise CommandError("Wrong command")

                    else:
                        try:
                            print(commands[command](assist, *(eval(arg) for arg in userinput.split()[1:])))
                        except TypeError as e:
                            if (f"{commands[command].__name__}()" in e.args[0]):
                                raise CommandError("Wrong arguments!" + os.linesep + e.args[0])
                            else: raise
                        except SyntaxError:
                            raise CommandError("Command syntax is incorrect. "
                                               "Enter command shortcut followed by parameters separated with spaces. "
                                               "Remember not to put spaces within single parameter :)")

                except CommandError as e: showError(e)
                except SerialCommunicationError as e: showError(e)
                except SerialError as e: showError(e)
                except DeviceError as e: showError(e)
                except NotImplementedError as e: showError(e)
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
