import struct
import sys
from itertools import cycle
from random import randrange
from typing import Union, Any, Tuple

import progressbar
from Transceiver import lrc
from Transceiver.errors import *
from Utils import bytewise, Logger, flag

from .core import Command, Signal, SignalsTree, Telemetry
from .errors import *


log = Logger('API')
log.setLevel('SPAM')



"""
   Command method API docstring micro-syntax:

   (..., ...) - method parameters
   [...]      - optional parameter
   .../...    - variations of parameter type
   ...|...    - variations of parameter value
   <...>      - lexeme bounds
   ...        - arbitrary number of elements
"""

ACK_OK = 0x00
ACK_BAD = 0xFF

CHECK_DATA = True
CHECK_LRC = True
SELFTEST_TIMEOUT_SEC = 5
TESTCHANNEL_DEFAULT_DATALEN = 255
TESTCHANNEL_MAX_DATALEN = 1023
TESTCHANNEL_DEFAULT_DATABYTE = 'AA'
BASE_SIGNAL_DESCRIPTOR_SIZE = 17


class TransceiverPlaceholder:
    def __getattr__(self, item):
        raise RuntimeError("Cannot perform transaction - 'api.transceiver' is not set")


transceiver = TransceiverPlaceholder()


def _ensureSignal_(signal: Union[int, Signal]):
    """ Check 'signal' argument to be Signal() object or convert
            signal number to Signal() by performing readSignalDescriptor() transaction
    """

    if isinstance(signal, int):
        signal = readSignalDescriptor(signal)
    elif not isinstance(signal, Signal):
        raise SignatureError(f"Invalid 'signal' argument - expected 'Signal' or 'int', "
                             f"got '{signal.__class__.__name__}'")
    return signal


def _ensureTelemetry_(tm: Telemetry):
    tm = tm or Telemetry.active
    if tm is None:
        raise RuntimeError("Missing active telemetry object")
    return tm


def transaction(data: bytes) -> bytes:
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
    transceiver.sendPacket(data + lrc(data))
    reply = transceiver.receivePacket()

    if CHECK_LRC and not lrc(reply):
        raise BadCrcError(f"Bad data checksum - expected '{bytewise(lrc(reply[:-1]))}', "
                          f"got '{bytewise(reply[-1:])}'. Reply discarded", data=reply)

    if (reply[0] != ACK_OK):
        raise BadAckError(data=reply)

    # Cut ACK and LRC bytes
    return reply[1:-1]


def sendCommand(command: str, data: str = '') -> bytes:
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
    return transaction(bytes.fromhex(command) + packet)


@Command(command='01 01', shortcut='chch', required=True, expReply=8, category=Command.Type.UTIL)
def checkChannel(data: str = None) -> bytes:
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

    reply = transaction(checkChannel.command + checkingData)

    if (reply != checkingData):
        raise DataInvalidError(f"Invalid reply - expected [{bytewise(checkingData)}], "
                               f"got [{bytewise(reply)}]", expected=checkingData, actual=reply)
    return reply


@Command(command='01 02', shortcut='r', required=False, expReply=False, category=Command.Type.UTIL)
def reset():
    """ API: reset()
        Return: None
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                DataInvalidError - reply contains extra data [configurable]
    """

    reply = transaction(reset.command)
    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='01 03', shortcut='i', required=True, expReply=True, category=Command.Type.UTIL)
def deviceInfo() -> str:
    """ API: deviceInfo()
        Return: Device info string
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                DataInvalidError - reply contains extra data [configurable]
                DataInvalidError - no zero byte found in reply string
    """

    reply = transaction(deviceInfo.command)

    try:
        infoBytes = reply.split(b'\x00', 1)[0]
    except IndexError:
        raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

    if CHECK_DATA: Command.checkStrExtra(infoBytes, reply)

    return infoBytes.decode('utf-8', errors='replace')


@Command(command='01 04', shortcut='sm', required=True, expReply=False, category=Command.Type.UTIL)
def scanMode(enable: bool):
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

    reply = transaction(scanMode.command + mode)

    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='01 05', shortcut='sft', required=False, expReply=True, category=Command.Type.UTIL)
def selftest() -> str:
    """ API: selftest()
        Return: Selftest result string
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                DataInvalidError - reply contains extra data [configurable]
                DataInvalidError - no zero byte found in reply string
    """

    savedTimeout = transceiver.timeout
    transceiver.timeout = SELFTEST_TIMEOUT_SEC

    reply = transaction(selftest.command)

    try:
        selftestResult = reply.split(b'\x00', 1)[0]
    except IndexError:
        raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

    if CHECK_DATA: Command.checkStrExtra(selftestResult, reply)
    transceiver.timeout = savedTimeout

    return selftestResult.decode('utf-8', errors='replace')


@Command(command='01 06', shortcut='ss', required=False, expReply=False, category=Command.Type.UTIL)
def saveSettings():
    """ API: saveSettings()
        Return: None
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                DataInvalidError - reply contains extra data [configurable]
    """

    reply = transaction(saveSettings.command)
    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='01 07', shortcut='tch', required=False, expReply=True, category=Command.Type.UTIL)
def testChannel(data: str = None, n: int = None) -> bytes:
    """ API: testChannel([data='XX XX ... XX'/'random'], [n=<data size in bytes>])
        Return: N bytes of test data received from device
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                SignatureError - invalid 'data' or 'n' arguments
                DataInvalidError - invalid reply from device
    """

    if n is None:
        n = TESTCHANNEL_DEFAULT_DATALEN
    elif not isinstance(n, int) or n < 0:
        raise SignatureError(f"Invalid data length ('n') - expected positive integer, got '{n}'")
    elif n > TESTCHANNEL_MAX_DATALEN:
        raise SignatureError(f"Data length ('n') should be no more than {TESTCHANNEL_MAX_DATALEN}")

    if data in ('r', 'random'):
        # NOTE: zeros are not allowed => range starts from 1
        checkingData = struct.pack(f'< {n}B', *(randrange(1, 0x100) for _ in range(n)))
    elif not data:
        checkingData = bytes.fromhex(TESTCHANNEL_DEFAULT_DATABYTE * n)
    else:
        try:
            dataSampleIterator = cycle(bytes.fromhex(data))
        except (ValueError, TypeError):
            raise SignatureError(f"Invalid hex data string - {data}")
        checkingData = bytes((dataSampleIterator.__next__() for _ in range(n)))
    log.debug(f"Tch hex data: {bytewise(checkingData, collapseAfter=25)}")

    checkingData += b'\x00'
    reply = transaction(testChannel.command + checkingData)

    if (reply != checkingData):
        raise DataInvalidError(f"Invalid reply - expected [{bytewise(checkingData, collapseAfter=25)}], "
                               f"got [{bytewise(reply, collapseAfter=25)}])",
                               expected=checkingData, actual=reply)
    return reply


@Command(command='03 01', shortcut='sc', required=True, expReply=2, category=Command.Type.SIG)
def signalsCount() -> int:
    """ API: signalsCount()
        Return: number of signals
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                DataInvalidError - failed to parse signals count number
    """

    reply = transaction(signalsCount.command)

    try:
        nSignals = struct.unpack('< H', reply)[0]
    except StructParseError:
        raise DataInvalidError(f"Cannot convert data to integer value: [{bytewise(reply)}]", data=reply)
    return nSignals


@Command(command='03 02', shortcut='rsd', required=True, expReply=True, category=Command.Type.SIG)
def readSignalDescriptor(signalNum: int) -> Signal:
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
        raise SignatureError(f"Invalid signal number - expected positive integer, got '{signalNum}'")

    reply = transaction(readSignalDescriptor.command + struct.pack('< H', signalNum))

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
                               reply[sigNameEndIndex + 1:][:BASE_SIGNAL_DESCRIPTOR_SIZE])
    except StructParseError:
        raise DataInvalidError(f"Failed to parse signal #{signalNum} descriptor struct: "
                               f"[{bytewise(reply[sigNameEndIndex + 1:])}]", data=reply)

    log.debug(f"Raw #{signalNum} '{name}' signal struct: {params}")

    signal = Signal.from_struct(signalNum, (name, *params))
    if signal.varclass is not Signal.Class.Std:
        raise NotImplementedError("Complex type class signals are not supported")

    log.verbose('\n' + signal.format())

    return signal


@Command(command='03 03', shortcut='ms', required=False, expReply=False, category=Command.Type.SIG)
def manageSignal(signal: Union[int, Signal], value: Any = None,
                 mode: Union[int, str, Signal.Mode] = None) -> Union[str, int, float, bool]:
    """ API: manageSignal(signal=Signal()/<signal number>, [value=<signal value>],
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
        TODO: fix 'Detail' - no additional transactions are performed now
    """

    # Check 'signal' argument
    signal = _ensureSignal_(signal)
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
        value = readSignal(signal)
    elif type(value) is not signal.vartype.pytype:
        log.warning(f"Invalid value for '{signal.name}' signal - expected "
                    f"'{signal.vartype.pytype.__name__}', got '{value.__class__.__name__}'")

    # Pack and send command
    commandParams = struct.pack('< H B', signal.n, mode)
    try:
        commandValue = struct.pack(f'< {signal.vartype.code}', value)
    except StructParseError:
        raise ValueError(f"Failed to assign '{value}' to '{signal.name}' signal")

    reply = transaction(manageSignal.command + commandParams + commandValue)

    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='03 04', shortcut='ssg', required=False, expReply=0, category=Command.Type.SIG)
def setSignature(*args):
    """ API: <NotImplemented> """
    raise NotImplementedError()


@Command(command='03 05', shortcut='rs', required=False, expReply=False, category=Command.Type.SIG)
def readSignal(signal: Union[int, Signal]) -> Any:
    """ API: readSignal(signal=Signal()/<signal number>)
        Detail: if 'signal' is signal number, additional descriptor query transaction is performed
        Raises: [SerialError] - transceiver exception
                BadAckError - device sent error acknowledgement
                BadCrcError - XOR check failed [configurable]
                SignatureError - invalid 'signal' argument
                DataInvalidError - reply contains extra data [configurable]
        TODO: fix 'Detail' - no additional transactions are performed now
    """

    signal = _ensureSignal_(signal)

    reply = transaction(readSignal.command + struct.pack('< H', signal.n))

    if signal.vartype == Signal.Type.String:
        try:
            valueBytes = reply.split(b'\x00', 1)[0]
        except IndexError:
            raise DataInvalidError('Cannot determine end of string - no null character found', data=reply)

        if CHECK_DATA: Command.checkStrExtra(valueBytes, reply)
        sigValue = valueBytes.decode('utf-8', errors='replace')

    else:
        try:
            sigValue = struct.unpack(f'< {signal.vartype.code}', reply)[0]
        except StructParseError:
            raise DataInvalidError(f"Failed to parse '{signal.name}' signal value: "
                                   f"[{bytewise(reply)}]", data=reply)

    return signal.vartype.pytype(sigValue)


'Basic telemetry monitoring session'

# PLAY
'reset'           '5A-0C-05-00-A0-F3 04-02 00 01 00 00 00 00 00 07 FB-F5'
'add signal'      '5A-0C-03-80-A2-73 04-03 01 00 06 00 F4-FC'
'start buffered'  '5A-0C-05-00-A0-F3 04-02 03 C8 00 00 00 00 00 CD F7-68'
'read data'       '5A-0C-02-80-A3-73 04-04 00 00 FB-FB'
'...'

# STOP
'reset'           '5A-0C-05-00-A0-F3 04-02 00 01 00 00 00 00 00 07 FB-F5'


@Command(command='04 01', shortcut='rtd', required=True, expReply=12, category=Command.Type.TELE)
def readTelemetryDescriptor(device: str = None) -> Telemetry:
    """ API: readTelemetryDescriptor([device='<device name>'])
        TODO: Raises, Return, etc.
    """

    if device is not None and not isinstance(device, str):
        raise SignatureError(f"Invalid 'device' argument - expected 'str', got {device.__class__.__name__}")

    reply = transaction(readTelemetryDescriptor.command)

    # Parse descriptor struct
    try:
        params = struct.unpack('< I H H I', reply)
    except StructParseError:
        raise DataInvalidError(f"Failed to parse telemetry descriptor: [{bytewise(reply)}]", data=reply)
    log.debug(f"Raw '{device}' telemetry struct: {params}")

    if (flag(params[3], 0) == 1): raise NotImplementedError("Stream transmission mode is not supported")
    if (flag(params[3], 1) == 1): raise NotImplementedError("Data framing is not supported")

    tm = Telemetry.from_struct(params, device)
    log.verbose('\n' + tm.format())

    return tm


@Command(command='04 02', shortcut='st', required=True, expReply=False, category=Command.Type.TELE)
def setTelemetry(mode: Union[int, str, Telemetry.Mode], divider: int = None,
                 frameSize: int = None):
    """ API: setTelemetry(mode=<0..4>/<reset|stream|framed|buffered|run|stop>/Telemetry.Mode,
                         [divider=<frequency split coefficient>], [frameSize=<samples per frame>])
    """

    # Check 'mode' argument
    Modes = Telemetry.Mode
    if isinstance(mode, Modes):
        pass  # already converted
    elif isinstance(mode, str):
        try:
            mode = Modes[mode.capitalize()]  # convert from string
        except KeyError:
            raise SignatureError(f"Invalid mode '{mode}' - expected within " +
                                 f"[{', '.join((s.lower() for s in Modes.__members__.keys()))}]")
    elif isinstance(mode, int):
        try:
            mode = Modes(mode)  # convert from int
        except ValueError:
            raise SignatureError(f"Invalid mode {mode} - expected within [0..{len(Modes) - 1}]")
    else:
        raise SignatureError(f"Invalid 'mode' argument - {mode}")

    # Check 'divider' argument
    if mode not in (Modes.Stop, Modes.Reset):  # TODO: update this to use new 'mode.running' property
        if divider is None:
            raise SignatureError(f"Missing 'divider' argument")
        if not isinstance(divider, int) or divider <= 0:
            raise SignatureError(f"Invalid frequency divider argument - expected integer > 0, got '{divider}'")

    # Check 'frameSize' argument
    if mode == Modes.Framed:
        if frameSize is None:
            raise SignatureError(f"Missing 'frameSize' argument")
        elif not isinstance(frameSize, int) or frameSize <= 0:
            raise SignatureError(f"Invalid dataframe size argument - expected integer > 0, got '{frameSize}'")

    reply = transaction(setTelemetry.command + struct.pack('< B I H', mode.value, divider or 1, frameSize or 0))

    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='04 03', shortcut='as', required=True, expReply=NotImplemented, category=Command.Type.TELE)
def addSignal(signal: Union[int, Signal]):
    """ API: addSignal(signal=Signal()/<signal number>) """

    signal = _ensureSignal_(signal)
    reply = transaction(addSignal.command + struct.pack('< H', signal.n))

    if CHECK_DATA: Command.checkEmpty(reply)


@Command(command='04 04', shortcut='rt', required=True, expReply=NotImplemented, category=Command.Type.TELE)
def readTelemetry() -> Tuple[Tuple[Union[int, float, str, bool]], Telemetry.Status]:
    """ API: readTelemetry() """

    return (transaction(readTelemetry.command), None)


def scanSignals(attempts: int = 2, *, tree: bool = True, init: bool = True,
                showProgress: bool = False) -> Tuple[Union[SignalsTree, tuple], tuple]:
    """ API: scanSignals(attempts=N, tree=True/False, showProgress=True/False)
                Detail:
                    'tree' - signals collection output format:
                        True -> SignalsTree()
                        False -> list of signals
                    'init' - signal.value initialization:
                        True -> readSignal() is called after each successful descriptor query
                        False -> signal is left with .value uninitialized (N/A)
                    'showProgress' - display ascii progressbar while performing scan
                Return:
                    2-element tuple:
                        • list of signals / signals tree
                        • tuple of signal indexes which failed to be acquired
                Raises: [signalsCount errors]
                        [readSignalDescriptor errors]
            """

    nSignals = signalsCount()
    failed = []  # indexes of signals which descriptor query failed

    if showProgress is True:
        progressbarElements = (
            progressbar.widgets.Bar(marker='█', left='', right='', fill='░'),
            ' ', progressbar.Percentage()
        )
        progress = progressbar.ProgressBar(widgets=progressbarElements, fd=sys.stdout)
    else:
        progress = iter

    target = SignalsTree(Signal.Root()) if tree is True else []

    log.info(f"Scanning {nSignals} signals...")

    for signalNum in progress(range(nSignals)):
        for _ in range(attempts):
            try:
                signal = readSignalDescriptor(signalNum)
                if init is True:
                    signal.value = readSignal(signal)
            except (BadAckError, SerialError):
                continue
            target.append(signal)
            break
        else:
            target.append(Signal.Unknown(signalNum))
            failed.append(signalNum)

    return target, tuple(failed)
