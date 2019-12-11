import struct
from itertools import cycle
from random import randrange
from typing import Union, Any

from Transceiver import Transceiver, lrc, BadCrcError

from PyAssist.config import CONFIG
from .core import Command, Signal
from .errors import *
from Utils import bytewise, Logger


log = Logger('API')
log.setLevel('SPAM')


class Assist:

    ACK_OK = 0x00
    ACK_BAD = 0xFF

    def __init__(self, transceiver: Transceiver):
        self.transceiver = transceiver

    def transaction(self, data: bytes) -> bytes:
        """ Perform basic DSP transaction:
                1) add LRC byte to 'data'
                2) send packet to the device
                3) receive reply packet
                4) verify LRC and ACK
                5) return reply payload data
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
        """
        self.transceiver.sendPacket(data + lrc(data))
        reply = self.transceiver.receivePacket()

        if CONFIG.CHECK_LRC and not lrc(reply):
            raise BadCrcError(f"Bad data checksum - expected '{bytewise(lrc(reply[:-1]))}', "
                              f"got '{bytewise(reply[-1:])}'. Reply discarded", data=reply)

        if (reply[0] != self.ACK_OK):
            raise BadAckError(f"Command execution failed", data=reply)

        # Cut ACK and LRC bytes
        return reply[1:-1]

    def sendCommand(self, command: str, data: str = '') -> bytes:
        """ Send command manually
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    SignatureError - invalid 'command' or 'data' hex strings provided
        """
        try:
            packet = bytes.fromhex(data)
        except (ValueError, TypeError):
            raise SignatureError(f"Invalid hex string: {' '.join((command, data))}")
        return self.transaction(bytes.fromhex(command) + packet)

    @Command(command='01 01', shortcut='chch', required=True, expReply=8, category=Command.Type.UTIL)
    def checkChannel(self, command: bytes, data: str = None) -> bytes:
        """ API: checkChannel([data='XX XX ... XX'/'random'])
            Return: 8 bytes of test data received from device
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    SignatureError - invalid test data provided
                    DataInvalidError - invalid reply from device
        """

        if data == 'random' or data == 'r':
            checkingData = struct.pack('< 8B', *(randrange(0, 0x100) for _ in range(8)))
        elif not data:
            checkingData = bytes.fromhex('01 23 45 67 89 AB CD EF')
        else:
            try:
                checkingData = bytes.fromhex(data)
            except (TypeError, ValueError):
                raise SignatureError(f"Invalid hex data string - {data}")
            if len(checkingData) != 8:
                raise SignatureError("Data length should be 8 bytes")

        reply = self.transaction(command + checkingData)

        if (reply != checkingData):
            raise DataInvalidError(f"Invalid reply - expected [{bytewise(checkingData)}], "
                                   f"got [{bytewise(reply)}]", expected=checkingData, actual=reply)
        return reply

    @Command(command='01 02', shortcut='r', required=False, expReply=False, category=Command.Type.UTIL)
    def reset(self, command: bytes):
        """ API: reset()
            Return: None
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
        """

        reply = self.transaction(command)

        if CONFIG.CHECK_DATA: Command.checkEmpty(reply)

    @Command(command='01 03', shortcut='i', required=True, expReply=True, category=Command.Type.UTIL)
    def deviceInfo(self, command: bytes) -> str:
        """ API: deviceInfo()
            Return: Device info string
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
                    DataInvalidError - no zero byte found in reply string
        """

        reply = self.transaction(command)

        try:
            infoBytes = reply.split(b'\x00', 1)[0]
        except IndexError:
            raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

        if CONFIG.CHECK_DATA: Command.checkStrExtra(infoBytes, reply)

        return infoBytes.decode('utf-8', errors='replace')

    @Command(command='01 04', shortcut='sm', required=True, expReply=False, category=Command.Type.UTIL)
    def scanMode(self, command: bytes, enable: bool):
        """ API: scanMode(True/False)
            Return: None
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
                    SignatureError - invalid 'mode' is provided
        """

        if enable in (True, 1, 'on'): mode = b'\x01'
        elif enable in (False, 0, 'off'): mode = b'\x00'
        else: raise SignatureError(f"Invalid mode - expected True/False, got {enable}")

        reply = self.transaction(command + mode)

        if CONFIG.CHECK_DATA: Command.checkEmpty(reply)

    @Command(command='01 05', shortcut='st', required=False, expReply=True, category=Command.Type.UTIL)
    def selftest(self, command: bytes) -> str:
        """ API: selftest()
            Return: Selftest result string
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
                    DataInvalidError - no zero byte found in reply string
        """

        savedTimeout = self.transceiver.timeout
        self.transceiver.timeout = CONFIG.SELFTEST_TIMEOUT_SEC

        reply = self.transaction(command)

        try:
            selftestResult = reply.split(b'\x00', 1)[0]
        except IndexError:
            raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

        if CONFIG.CHECK_DATA: Command.checkStrExtra(selftestResult, reply)
        self.transceiver.timeout = savedTimeout

        return selftestResult.decode('utf-8', errors='replace')

    @Command(command='01 06', shortcut='ss', required=False, expReply=False, category=Command.Type.UTIL)
    def saveSettings(self, command: bytes):
        """ API: saveSettings()
            Return: None
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
        """

        reply = self.transaction(command)

        if CONFIG.CHECK_DATA: Command.checkEmpty(reply)

    @Command(command='01 07', shortcut='tch', required=False, expReply=True, category=Command.Type.UTIL)
    def testChannel(self, command: bytes, data: str = None, n: int = None) -> bytes:
        """ API: testChannel([data='XX XX ... XX'/'random'], [n=<data size in bytes>])
            Return: N bytes of test data received from device
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    SignatureError - invalid 'data' or 'n' arguments
                    DataInvalidError - invalid reply from device
        """

        if n is None:
            n = CONFIG.TESTCHANNEL_DEFAULT_DATALEN
        elif not isinstance(n, int) or n < 0:
            raise SignatureError(f"Data length ('n') should be positive integer, not '{n}'")
        elif n > CONFIG.TESTCHANNEL_MAX_DATALEN:
            raise SignatureError(f"Data length ('n') should be no more than {CONFIG.TESTCHANNEL_MAX_DATALEN}")

        if data in ('r', 'random'):
            # NOTE: zeros are not allowed => range starts from 1
            checkingData = struct.pack(f'< {n}B', *(randrange(1, 0x100) for _ in range(n)))
        elif not data:
            checkingData = bytes.fromhex(CONFIG.TESTCHANNEL_DEFAULT_DATABYTE * n)
        else:
            try:
                dataSampleIterator = cycle(bytes.fromhex(data))
            except (ValueError, TypeError):
                raise SignatureError(f"Invalid hex data string - {data}")
            checkingData = bytes((dataSampleIterator.__next__() for _ in range(n)))
        log.debug(f"Tch hex data: {bytewise(checkingData, collapseAfter=25)}")

        checkingData += b'\x00'
        reply = self.transaction(command + checkingData)

        if (reply != checkingData):
            raise DataInvalidError(f"Invalid reply - expected [{bytewise(checkingData, collapseAfter=25)}], "
                                   f"got [{bytewise(reply, collapseAfter=25)}])",
                                   expected=checkingData, actual=reply)
        return reply

    @Command(command='03 01', shortcut='sc', required=True, expReply=2, category=Command.Type.SIG)
    def signalsCount(self, command: bytes) -> int:
        """ API: signalsCount()
            Return: number of signals
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - failed to parse signals count number
        """

        reply = self.transaction(command)

        try:
            nSignals = struct.unpack('< H', reply)[0]
        except StructParseError:
            raise DataInvalidError(f"Cannot convert data to integer value: [{bytewise(reply)}]", data=reply)
        return nSignals

    @Command(command='03 02', shortcut='rsd', required=True, expReply=True, category=Command.Type.SIG)
    def readSignalDescriptor(self, command: bytes, signalNum: int) -> Signal:
        """ API: readSignalDescriptor(signalNum=<signalNum number>)
            Return: Signal() object (value is not set)
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    SignatureError - invalid 'signalNum' argument
                    DataInvalidError - failed to parse signal descriptor
                    NotImplementedError - signal class is complex, not supported currently
        """

        if not isinstance(signalNum, int) or signalNum < 0:
            raise SignatureError(f"Signal number should be positive integer, not '{signalNum}'")

        reply = self.transaction(command + struct.pack('< H', signalNum))

        # Parse signal name
        try:
            sigNameEndIndex = reply.find(b'\x00')
        except ValueError:
            raise DataInvalidError(f"Cannot parse signal #{signalNum} descriptor field #1 (name) - "
                                   f"no null character found")
        name = reply[:sigNameEndIndex].decode('utf-8', errors='replace')

        # Parse descriptor struct
        try:
            params = struct.unpack('< B B I h I B f',
                                   reply[sigNameEndIndex + 1:][:CONFIG.BASE_SIGNAL_DESCRIPTOR_SIZE])
        except StructParseError:
            raise DataInvalidError(f"Failed to parse signal #{signalNum} descriptor struct: "
                                   f"[{bytewise(reply[sigNameEndIndex + 1:])}]", data=reply)

        log.debug(f"Raw #{signalNum} '{name}' signal struct: {params}")

        signal = Signal.from_struct(signalNum, (name, *params))
        if signal.varclass is not Signal.Class.Std:
            raise NotImplementedError("Complex type class signals are not supported")

        log.verbose('\n'+signal.descriptor)

        return signal

    @Command(command='03 03', shortcut='ms', required=False, expReply=False, category=Command.Type.SIG)
    def manageSignal(self, command: bytes, signal: Union[int, Signal],
                     value: Any = None, mode: Union[int, str, Signal.Mode] = None) -> Any:
        """ API: manageSignal(signal=Signal()/<signal number>,
                             [value=<signal value>],
                             [mode=<0|1|2>/<free|fixed|sign>/Signal.Mode])
            Detail: Additional 'read signal' transaction is performed
                        after 'manage signal' transaction to synchronize signal value
                    If 'signal' is an integer (signal number),
                        additional descriptor query transaction is performed
                    If 'mode' or 'value' arguments are not specified,
                        corresponding signal parameters are left unchanged
                    Argument 'mode' is case-insensitive
            Return: Synchronized signal value
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    DataInvalidError - reply contains extra data [configurable]
                    SignatureError - invalid 'signal' or 'mode' argument
                    ValueError - failed to assign value 'value' to 'signal'
                    NotImplementedError - Mode.Sign
                    NotImplementedError - Signal.Type.String
        """

        # Check 'signal' argument
        if isinstance(signal, int):
            signal = self.readSignalDescriptor(signal)
        elif not isinstance(signal, Signal):
            raise SignatureError(f"Invalid 'signal' argument - expected 'Signal' or 'int', "
                                 f"got '{signal.__class__.__name__}'")
        if signal.vartype == Signal.Type.String:
            raise NotImplementedError(f"Cannot assign value to string-type signal "
                                      "(for what on Earth reason do you wanna do that btw???)")

        # Check 'mode' argument
        Modes = Signal.Mode
        if mode is None:
            mode = signal.mode.value
        elif isinstance(mode, Modes):
            mode = mode.value  # convert to mode index
        elif isinstance(mode, str):
            try:
                mode = Modes[mode.capitalize()].value  # convert to mode index
            except KeyError:
                raise SignatureError(f"Invalid mode '{mode}' - expected within " +
                                     f"[{', '.join((s.lower() for s in Modes.__members__.keys()))}]")
        elif isinstance(mode, int) and mode >= len(Modes):
            raise SignatureError(f"Invalid mode {mode} - expected within [0..{len(Modes) - 1}]")
        else:
            raise SignatureError(f"Invalid 'mode' argument - {mode}")
        if mode == Modes.Sign:
            raise NotImplementedError("Signature control mode is not supported")

        # Check 'value' argument
        if value is None:
            value = self.readSignal(signal)
        else:
            if type(value) is not signal.vartype.pytype:
                raise ValueError(f"Invalid value type for '{signal.name}' signal - "
                                 f"expected '{signal.vartype.pytype.__name__}', "
                                 f"got '{value.__class__.__name__}'")

        # Pack and send command
        commandParams = struct.pack('< H B', signal.n, mode)
        try:
            commandValue = struct.pack(f'< {signal.vartype.code}', value)
        except StructParseError:
            raise ValueError(f"Failed to assign '{value}' to '{signal.name}' signal")

        reply = self.transaction(command + commandParams + commandValue)

        if CONFIG.CHECK_DATA: Command.checkEmpty(reply)
        signal.mode = Signal.Mode(mode)

        # Sync signal value
        self.readSignal(signal)  # CONSIDER: do I need this and how to sync properly?

        return signal.value

    @Command(command='03 04', shortcut='ssg', required=False, expReply=0, category=Command.Type.SIG)
    def setSignature(self, command: bytes, *args):
        """ API: <NotImplemented> """
        raise NotImplementedError()

    @Command(command='03 05', shortcut='rs', required=False, expReply=False, category=Command.Type.SIG)
    def readSignal(self, command: bytes, signal: Union[int, Signal]) -> Any:
        """ API: readSignal(signal=Signal()/<signal number>)
            Detail: if 'signal' is signal number, additional descriptor query transaction is performed
            Raises: [SerialError] - transceiver exception
                    BadAckError - device sent error acknowledgement
                    BadCrcError - XOR check failed [configurable]
                    SignatureError - invalid 'signal' argument
                    DataInvalidError - reply contains extra data [configurable]
        """

        if isinstance(signal, int):
            signal = self.readSignalDescriptor(signal)
        elif not isinstance(signal, Signal):
            raise SignatureError(f"Invalid 'signal' argument - expected 'Signal' or 'int', "
                                 f"got '{signal.__class__.__name__}'")

        reply = self.transaction(command + struct.pack('< H', signal.n))

        if signal.vartype == Signal.Type.String:
            try:
                valueBytes = reply.split(b'\x00', 1)[0]
            except IndexError:
                raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

            if CONFIG.CHECK_DATA: Command.checkStrExtra(valueBytes, reply)
            sigValue = valueBytes.decode('utf-8', errors='replace')

        else:
            try:
                sigValue = struct.unpack(f'< {signal.vartype.code}', reply)[0]
            except StructParseError:
                raise DataInvalidError(f"Failed to parse '{signal.name}' signal value: "
                                       f"[{bytewise(reply)}]", data=reply)

        sigValue = signal.vartype.pytype(sigValue)
        signal.value = sigValue

        return sigValue

# TODO: telemetry handling methods
