from __future__ import annotations as _
import re
from enum import Enum, Flag, unique
from functools import wraps, partial, partialmethod
from itertools import dropwhile
from types import MethodType
from typing import Union, Callable, ClassVar, Optional, Collection, Sequence, List, Dict, TypeVar

from CPython.Lib.functools import singledispatchmethod
from Transceiver import SerialError, Transceiver
from Utils import Logger, bytewise, auto_repr, classproperty, Null, formatDict, AttrEnum, store
from src.Experiments.attr_tagging_concise import Classtools, TAG, const

from . import api
from .config import CONFIG
from .errors import *


log = Logger('Core')
log.setLevel('SPAM')


# ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————— #

# ✓ Access children of a signal through its name (like 'Parent.Children')

# CONSIDER: struct.Struct optimization in Signal and API

# ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————— #


stubs = dict(
        notAssigned = '<N/A>',
        noNameAttr  = '<NoName>',
        noFlags  ='<NoFlags>',
        noSignals = '<NoSignals>',
        rootSignal  = '<Root>',
        emptyTree = '<Empty>',
        unknownSignal = '<#{} Unknown>',
)


class Command():
    __slots__ = ('shortcut', 'command', 'required', 'expReply', 'type')

    methodNameRegex = re.compile(r'((?<=[a-z])[A-Z])')

    # Map [full command method names] to [command methods themselves] ▼
    ALL = {}

    class Type(Enum):
        NONE = 0
        UTIL = 1
        PROG = 2
        SIG = 3
        TELE = 4

    def __init__(self, command: str, shortcut: str, required=False, expReply=None, category=Type.NONE):
        try:
            if (len(bytes.fromhex(command)) != 2): raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"'command' should be a valid 2 bytes hex string representation, not {command}")

        if (not isinstance(category, self.Type)):
            raise TypeError(f"'category': expected '{self.Type.__class__.__name__}' member, "
                            f"got '{category.__class__.__name__}'")

        # Command id (2 bytes hex string representation)
        self.command: bytes = bytes.fromhex(command)

        # API alias
        self.shortcut: str = shortcut

        # Compulsory/optional command flag
        self.required: bool = bool(required)

        # Expected reply data presence / length
        #   True - reply should contain some data apart from ACK and LRC
        #   False - reply should NOT contain any data except for ACK and LRC
        #   None - reply data check is not performed
        #   N - reply should contain exactly N bytes
        self.expReply: Union[bool, int, None] = expReply

        # Command category
        self.type: Command.Type = category

    def __call__(self, fun):
        @wraps(fun)
        def wrapper(*args, **kwargs):

            # Convert 'CamelCase' to 'Capitalized words sequence'
            commandName = re.sub(self.methodNameRegex, r' \1', fun.__name__).capitalize()
            log.debug(f"{commandName}...")

            try:
                result = fun(*args, **kwargs)
            except BadAckError:
                log.error(f"{commandName}: Bad ACK")
                raise
            except (SerialError, DeviceError) as e:
                log.error(f"{commandName}: {e.__class__.__name__}")
                raise

            log.debug(f"{commandName}: OK")
            return result

        wrapper.command = self.command
        wrapper.shortcut = self.shortcut
        wrapper.required = self.required
        wrapper.expReply = self.expReply
        wrapper.type = self.type

        self.ALL[fun.__name__] = wrapper

        return wrapper

    @staticmethod
    def checkEmpty(result: bytes):
        if result is not b'':
            raise DataInvalidError(f"Got unexpected reply data: [{bytewise(result)}]", data=result)

    @staticmethod
    def checkStrExtra(result: bytes, actual: bytes):
        if len(actual) > len(result) + 1:
            raise DataInvalidError(f"Got extra reply data after end-of-string - "
                                   f"{result[len(actual) + 1:].decode('utf-8', errors='replace')}", data=result)

    @staticmethod
    def getCommandApi(commandMethod: Callable) -> str:
        docstring = commandMethod.__doc__
        methodName = commandMethod.__name__
        if docstring is None:
            return '<Not found>'
        try:
            methodNameStartIndex = docstring.index('API: ') + 5
        except ValueError:
            raise ValueError(f"Cannot find API signature in {methodName}() method docstring")

        bracketsLevel = 0
        endIndex = docstring.find('\n')

        for pos, char in enumerate(docstring[methodNameStartIndex:], start=methodNameStartIndex):
            if char == '(':
                if bracketsLevel == 0:
                    openBracketIndex = pos
                    apiName = docstring[methodNameStartIndex:openBracketIndex]
                    if not apiName.isidentifier():
                        raise ValueError(f"Invalid API signature method name '{apiName}'")
                    if apiName != methodName:
                        raise ValueError(f"API signature method name '{apiName}' "
                                         f"does not match actual command method name '{methodName}'")
                bracketsLevel += 1

            elif char == ')':
                bracketsLevel -= 1
                if bracketsLevel == 0:
                    endIndex = pos + 1
                    break
        if '\n' in docstring[methodNameStartIndex:endIndex]:
            return ' '.join(docstring[methodNameStartIndex:endIndex].split())
        else:
            return docstring[methodNameStartIndex:endIndex]


class ParamEnum(AttrEnum):
    def __str__(self):
        return self.name

    def __index__(self):
        return self.value


class ParamFlagEnum(ParamEnum, Flag):
    """
        It is recommended to set value as 1 << n
    """
    def __str__(self):
        return Flag.__str__(self)[self.__class__.__name__.__len__()+1:]


class SignalsTree:
    """ Container for Signal objects
            Allows for efficient elements access both by integer indexes and string names
            len() returns actual number of stored Signal objects
        Usage:
            >>> signals = SignalsTree()
            >>> signals.append(Signal('Test', ...))
            >>> signals[0]
            <Signal Test = ... at 0x...>
            >>> signals['Test']
            <Signal Test = ... at 0x...>
    """

    # Automatically add Attrs.Node flag to node signal when constructing a tree
    ASSIGN_NODE = True

    def __init__(self, root=None):
        self.root = root if root is not None else Signal.Root()
        self.data: List[Union[Signal, Signal.Unknown]] = []  # (access by index)
        self.names: Dict[Signal.Name, Union[Signal, List[Signal]]] = {}  # (access by name)

    @singledispatchmethod
    def __getitem__(self, key: object):
        raise TypeError(f"Invalid key type - expected 'str' or 'int', got '{key.__class__.__name__}'")

    @__getitem__.register(int)
    def getByIndex(self, key: int) -> Union[Signal, Signal.Unknown]:
        return self.data[key]

    @__getitem__.register(str)
    def getByName(self, key: str) -> Signal:
        # Try to get signal by name (or by last fullname component, if hierarchical name is given)
        name: str = key.rsplit('.', maxsplit=1)[-1]
        item: Union[Signal, list] = self.names[name]

        # If fetched signal object, we are lucky
        if isinstance(item, Signal):
            return item

        # Else, we got a list of signals with coincident names
        # Go search among obtained signals list (item) by full name component provided (key)
        else:
            matches = tuple(signal for signal in self.names[name] if signal.fullname.endswith(key))
            if len(matches) == 1:
                return matches[0]
            else:
                raise KeyError(f"Ambiguous signal name '{key}' - "
                               f"[{', '.join(signal.fullname for signal in matches)}]")

    def append(self, signal: Union[Signal, Signal.Unknown]):
        if isinstance(signal, Signal.Unknown):
            self.data.append(signal)
            self.root.children[signal.name] = signal
            return
        if not isinstance(signal, Signal):
            raise TypeError(f"Only 'Signal' entries are allowed, got '{signal.__class__.__name__}'")
        if signal.n != len(self.data):
            raise ValueError("Signals should be added in-order - "
                             f"expected signal number {len(self.data)}, got {signal.n}")

        self.data.append(signal)

        name = signal.name
        if name not in self.names:
            self.names[name] = signal
        elif isinstance(self.names[name], Signal):
            self.names[name] = [self.names[name], signal]
        else:
            self.names[name].append(signal)

        parentNum = signal.parent
        if parentNum == -1:  # parent is Root
            Signal.parent.slot.__set__(signal, self.root)
            signal.fullname = name
        else:  # parent is some other signal
            Signal.parent.slot.__set__(signal, self.data[parentNum])
            signal.fullname = f"{signal.parent.fullname}.{name}"
            if self.ASSIGN_NODE is True and not isinstance(signal.parent, Signal.Unknown):
                Signal.attrs.slot.__set__(signal.parent, signal.attrs | Signal.Attrs.Node)

        signal.parent.children[name] = signal
        signal.children = {}

    def copy(self):
        dup = self.__class__()
        dup.data = self.data.copy()
        dup.names = self.names.copy()
        return dup

    def __str__(self, smooth=False):
        """ Render signals tree
            Raises:
                RecursionError - signals tree contains cycle references
        """

        if not self.root.children: return stubs['emptyTree']

        line, fork, end, void = '│   ', '├── ', '╰── ' if smooth else '└── ', '    '
        lines = []

        def render(prefix: str, signals: Collection[Signal]):
            last = len(signals)-1
            for i, signal in enumerate(signals):
                lines.append(''.join((prefix, end if i is last else fork, str(signal))))
                if signal.children:
                    render(prefix + (void if i is last else line), signal.children.values())

        lines.append(str(self.root))
        render('', self.root.children.values())
        return '\n'.join(lines)

    def __repr__(self):
        return f"{self.__class__.__name__} ({len(self.data)} items)"

    def __len__(self):
        return self.data.__len__()

    def __contains__(self, signal):
        return signal in self.data

    def __iter__(self):
        return iter(self.data)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data == other.data
        raise NotImplementedError


class Signal(metaclass=Classtools, slots=True, init=False):
    """ Signal docstring
        NOTE: if parent of some bundle of signals is <Unknown>,
              reference to all those signals would be garbage-collected :)
    """

    Name = TypeVar('Name', bound=str)  # Signal name

    class Root():
        """ Idle container class for top-level Signal objects
            Used to access those signals, in signals tree rendering
        """

        def __init__(self):
            self.n = -1
            self.name: Signal.Name = stubs['rootSignal']
            self.children: Dict[Signal.Name, Signal] = {}

        def __str__(self):
            return self.name

        def __repr__(self):
            return auto_repr(self, 'signal')

    class Unknown:
        """ Idle placeholder class to represent unknown signal """

        __slots__ = 'n', 'name', 'fullname', 'children', 'parent'
        def __init__(self, n: int):
            self.n = n
            self.name = stubs['unknownSignal'].format(n)
            self.fullname = self.name
            self.children = {}

        def __str__(self):
            return self.name

        def __repr__(self):
            return auto_repr(self, 'signal')

        def __hash__(self):
            return hash(self.n)

    class ScanModeDescriptor:
        """ Scan mode flag and context manager to enable scanMode inside its body """

        def __init__(self):
            self.enabled = False

        def __enter__(self):
            api.scanMode(True)
            self.enabled = True
            log.info("Scan mode: on")

        def __exit__(self, exc_type, exc_val, exc_tb):
            api.scanMode(False)
            self.enabled = False
            log.info("Scan mode: off")

        def __get__(self, instance, owner):
            if instance is None: return self
            return self.enabled

    @unique
    class Mode(ParamEnum):
        Free = 0  # Device-driven
        Fixed = 1  # Assist-driven
        Sign = 2  # Signature-driven

    @unique
    class Class(ParamEnum):
        Std = 0
        Enum = 1
        Array = 2
        Matrix = 3

    @unique
    class Type(ParamEnum):
        __names__ = 'value', 'code', 'pytype'

        String = 0, '' , str    # type 0: char[]  -> N bytes
        Bool =   1, 'B', bool   # type 1: uint_8  -> 1 byte
        Byte =   2, 'B', int    # type 2: uint_8  -> 1 byte
        Uint =   3, 'H', int    # type 3: uint_16 -> 2 bytes
        Int =    4, 'h', int    # type 4: int_16  -> 2 bytes
        Long =   5, 'i', int    # type 5: int_32  -> 4 bytes
        Ulong =  6, 'I', int    # type 6: uint_32 -> 4 bytes
        Float =  7, 'f', float  # type 7: float   -> 4 bytes

    @unique
    class Attrs(ParamFlagEnum):
        Control = 1 << 0
        Node = 1 << 1
        Signature = 1 << 2
        Read = 1 << 3
        Setting = 1 << 4
        Telemetry = 1 << 5

    @unique
    class Dimen(ParamEnum):
        __names__ = 'value', 'sign'

        Unitless = 0, ''
        Volt = 1, 'V'
        Ampere = 2, 'A'
        Deg = 3, '°'
        Rad = 4, 'rad'
        Meter = 5, 'm'
        VoltPerCelsius = 6, 'V/°C'
        MeterPerSecond = 7, 'm/s'
        Celsius = 8, '°C'
        CelsiusPerSecond = 9, '°C/s'

    class Signature:
        NotImplemented

        def __repr__(self): return str(NotImplemented)

    transceiver: ClassVar[Transceiver]
    scanMode: ClassVar[bool] = ScanModeDescriptor()
    tree: ClassVar[SignalsTree] = SignalsTree(Root())

    # Assist-defined parameters
    with TAG('service') |const:
        n: int
        fullname: str  # is not assigned if .parent is not resolved
        children: Optional[Dict[Name, Signal]]  # should be used only when tree is constructed

    # Descriptor-defined parameters
    with TAG('params') |const:
        name: Name
        varclass: Class
        vartype: Type
        attrs: Attrs
        parent: Union[Signal, Root, int]
        period: int
        dimen: Dimen
        factor: float

    # Signal-defined parameters
    with TAG('variables'):
        value: Union[str, int, float, bool] = None
        mode: Mode = Mode.Free
        signature: Signature = NotImplemented

    def __init__(self, n: int, name: Name,
                 varclass: Union[Class, int],
                 vartype: Union[Type, int],
                 attrs: Union[Attrs, int],
                 parent: Union[Signal, Root, int, None],  # parent=None -> .parent is not assigned
                 period: int = 10000,
                 dimen: Union[Dimen, int] = Dimen.Unitless,
                 factor: float = 1.0,
    ):
        """ Create Signal object on its own (unbound from SignalsTree) """

        self.n = n

        self.name = name  # CONSIDER: name.strip()?
        self.varclass = self.Class(varclass)
        self.vartype = self.Type(vartype)
        self.attrs = self.Attrs(attrs)
        self.period = int(period)
        self.dimen = self.Dimen(dimen)
        self.factor = float(factor)

        for name in ('value', 'mode', 'signature'):
            setattr(self, name, Signal[name].default)

        if parent is not None:
            if isinstance(parent, int):
                self.parent = parent
            elif isinstance(parent, (Signal, Signal.Root)):
                self.parent = parent
                self.fullname = f"{self.parent.name}.{name}"
            else:
                raise TypeError(f"Invalid 'parent' parameter type: "
                                f"expected 'Signal', 'Root' or 'int', got {type(parent)}")

    @classmethod
    def from_struct(cls, n: int, params: Sequence) -> Signal:
        """ Create Signal object and initialize it with `params` arguments
            Parameters are expected to be in order specified by Signal class
            No parameter type / value verification checks are performed

            Usage:
            >>> signal = Signal.from_struct(signal_n, (signal_name, *descriptor_params))
        """

        this = cls.__new__(cls)
        this.n = n

        for i, name in enumerate(cls.__tags__['params']):
            try:
                value = int(params[i]) if name == 'parent' else cls[name].type(params[i])
            except (ValueError, TypeError) as e:
                raise DataInvalidError(f"Invalid signal #{n} descriptor parameter '{name}' - {e.args[0]}")
            setattr(this, name, value)

        for name in ('value', 'mode', 'signature'):
            setattr(this, name, cls[name].default)

        return this

    def copy(self, **kwargs):  # TESTME
        #CONSIDER: Do I need to remove .children from copied signal
        #    (maybe there will be a risk of cycle references when signal will be added to SignalsTree?)
        new = self.__new__(self.__class__)
        for name in self.__slots__:
            try:
                value = getattr(self, name)
            except AttributeError:
                continue
            if name in kwargs:
                newValue = kwargs[name]
                if isinstance(newValue, self.__class__[name].type):
                    value = newValue
                else:
                    raise TypeError(f"Invalid '{name}' attr of '{self.name}' signal copy: "
                                    f"expected '{type(value)}', got '{type(newValue)}'")
            setattr(new, name, value)
        return new

    @classproperty
    def attrNamesWidth(cls):
        """ Service property. Computes length (in characters) of all Signal attrs """
        width = max(len(name) for name in cls.__attrs__)
        setattr(cls, 'attrNamesWidth', width)
        return width

    def format(self) -> str:
        lines = []
        for name in ('n', 'name', 'fullname', 'value', 'mode', 'varclass', 'vartype',
                     'attrs', 'parent', 'period', 'dimen', 'factor', 'signature'):
            lines.append(f"{name.rjust(self.attrNamesWidth)} - "
                         f"{getattr(self, name, stubs['notAssigned'])}")
        children = f"[{', '.join(getattr(self, 'children'))}]" if hasattr(self, 'children') else stubs['notAssigned']
        lines.append(f"{'children'.rjust(self.attrNamesWidth)} - {children}")
        return '\n'.join(lines)

    def __str__(self):
        name = self.name or stubs['noNameAttr']
        if self.value == '':
            return name
        elif self.value is None:
            value = stubs['notAssigned']
        elif self.vartype == self.Type.String:
            value = f"'{self.value}'"
        elif self.vartype == self.Type.Float and self.value is not Null:
            value = round(self.value, 3)
        else:
            value = self.value
        return f"{name}={value}"

    def __repr__(self):
        return auto_repr(self,
            "#{n} {name} = {value}{factor}{dimen} <{type}> {{{mode}}} {attrs}".format(
                n = self.n,
                name = self.fullname if hasattr(self, 'fullname') else self.name or stubs['noNameAttr'],
                value = round(self.value, 3)
                        if self.value is not None and self.vartype == self.Type.Float
                        else self.value,
                factor = f" ×{round(self.factor, 3)}" * (self.factor != 1 and self.value is not Null),
                dimen = self.dimen.sign * (self.dimen is not self.Dimen.Unitless and self.value is not Null),
                type = self.vartype,
                mode = self.mode,
                attrs = self.attrs,
            )
        )

    def __getattr__(self, name):
        fetch = partial(object.__getattribute__, self)
        try: return fetch('children')[name]
        except KeyError: raise AttributeError

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.n == other.n
        raise NotImplementedError


class Telemetry(metaclass=Classtools, slots=True):

    # CONSIDER: Telemetry() will return active tm object

    class Mode(ParamEnum):
        __names__ = 'value', 'running', 'state'

        Reset = 0, False, 'OFF'
        Stream = 1, True, 'RUNNING (stream)'
        Framed = 2, True, 'RUNNING (framed)'
        Buffered = 3, True, 'RUNNING (buffered)'
        Stop = 4, False, 'STOPPED'

    @unique
    class Status(ParamFlagEnum):
        Disabled = 0
        OK = 1 << 0
        Overflow = 1 << 1
        Error1 = 1 << 2
        Error2 = 1 << 3
        Error3 = 1 << 4
        Error4 = 1 << 5
        NoData = 1 << 6
        BadFrame = 1 << 7

    @unique
    class Attrs(ParamFlagEnum):
        Streaming = 1 << 0  # continuous transmission of data samples
        Framing = 1 << 1    # divide data in frames and send it on .readData command
        Buffering = 1 << 2  # send data on .readData command

    active: ClassVar[Telemetry] = None

    # Assist-defined parameters
    with TAG('service'):
        name: str = Null

    # Descriptor-defined parameters
    with TAG('params') |const:
        minPeriod: float #μs
        maxNumSignals: int
        maxFrameSize: int
        attrs: Attrs

    # Telemetry-defined parameters
    with TAG('variables'):
        divider: int = Null  # TODO: change to None, remove Null everywhere
        frameSize: int = Null
        mode: Mode = Mode.Reset |const
        status: Status = Status.Disabled |const
        signals: List[Signal] = [] |const

    @classmethod
    def new(cls, name: str = None):
        this = api.readTelemetryDescriptor(name)
        if name: this.name = name
        cls.active = this
        return this

    @classmethod
    def from_struct(cls, params: Sequence, device: str = None) -> Telemetry:
        """ Create Telemetry object and initialize it with `params` arguments
            Usage:
            >>> tm = Telemetry.from_struct(device_name, descriptor_params))
        """

        this = cls.__new__(cls)
        this.name = device or Telemetry['name'].default

        for i, name in enumerate(cls.__tags__['params']):
            try:
                value = cls[name].type(params[i])
            except (ValueError, TypeError) as e:
                raise DataInvalidError(f"Invalid telemetry descriptor parameter '{name}' - {e.args[0]}")
            setattr(this, name, value if name != 'minPeriod' else value/100)

        for name in Telemetry.__tags__['variables']:
            value = Telemetry[name].default
            setattr(this, name, value.copy() if hasattr(value, 'copy') else value)

        return this

    @classproperty
    def attrNamesWidth(cls):
        """ Service property. Computes length (in characters) of all Telemetry attrs """
        width = max(len(name) for name in cls.__attrs__)
        setattr(cls, 'attrNamesWidth', width)
        return width

    @property
    def frequency(self) -> float: #Hz
        return 1_000_000 / (self.minPeriod * self.divider) if self.divider else Null

    @property
    def period(self) -> float: #μs
        return self.minPeriod * self.divider if self.divider else Null

    def format(self) -> str:
        lines = []

        for name in ('name', 'mode', 'status', 'minPeriod', 'divider', 'frequency',
                     'attrs', 'frameSize', 'maxFrameSize', 'maxNumSignals'):
            lines.append(f"{name.rjust(self.attrNamesWidth)} - "
                         f"{getattr(self, name, stubs['notAssigned'])}")
        signals = (signal.name for signal in self.signals)
        lines.append(f"{'signals'.rjust(self.attrNamesWidth)} - [{', '.join(signals)}]")
        return '\n'.join(lines)

    def __str__(self):
        header = f"Telemetry '{self.name}'" if self.name is not Null else 'Telemetry'
        return f"{header}: {self.mode.state} <{self.status}> [{len(self.signals)}]"

    def __repr__(self):
        return auto_repr(self,
            "{name}: {mode}{status}{perf}{frameSize} {attrs} [{signals}]".format(
                name = f"Telemetry '{self.name}'" if self.name is not Null else 'Telemetry',
                mode = self.mode.state,
                status = f' <{self.status}>' if self.mode not in (self.Mode.Reset, self.Mode.Stop) else '',
                perf = f' ({self.formatPeriod(self.period)}, {self.formatFreq(self.frequency)})'
                       if self.divider else '',
                frameSize = f' {self.frameSize} samples/frame ' if self.Attrs.Framing in self.attrs else '',
                attrs = self.attrs,
                signals = ', '.join(s.name for s in self.signals) if self.signals else stubs['noSignals'],
            )
        )

    @staticmethod
    def formatValue(value: Union[int, float], digits=2, *, baseQuantity: str) -> str:
        multipliers = 'μ', 'm', '', 'K', 'M', 'G'
        try:
            base = multipliers.index(baseQuantity[0])
        except ValueError:
            base = 2  # index of an empty multiplier

        if value > 1_000_000:
            return f'{round(value / 1_000_000_000, digits)}{multipliers[base+3]}{baseQuantity[1:]}'
        if value > 1_000_000:
            return f'{round(value / 1_000_000, digits)}{multipliers[base+2]}{baseQuantity[1:]}'
        if value > 1000:
            return f'{round(value / 1_000, digits)}{multipliers[base+1]}{baseQuantity[1:]}'
        else:
            return f'{round(value, digits)}{baseQuantity}'

    formatFreq: ClassVar[MethodType] = partialmethod(formatValue, baseQuantity='Hz')

    formatPeriod: ClassVar[MethodType] = partialmethod(formatValue, baseQuantity='μs')

    @store(stored_signals=None)
    def run(self, mode: Telemetry.Mode = None) -> bool:
        """ Set telemetry mode to 'mode'.
            If 'mode' is not provided, most suitable mode is chosen automatically
            Device signals list is updated beforehand if changed since last run
        """

        # Choose the highest mode declared to be supported by .attrs
        if mode is None:
            mode = self.Mode(
                dropwhile(lambda member: member.value > self.attrs.value, reversed(self.Attrs))
                    .__next__().index + 1
            )

        # Make sure 'mode' has valid type
        elif not isinstance(mode, self.Mode):
            raise ValueError(f"Invalid mode - expected Mode enum, got '{mode.__class__.__name__}'")

        # Stop before relaunching
        if self.mode.running is True:
            actionName = "Restarting"
            self.stop()

        # Stop or reset if respective mode is provided
        else:
            actionName = "Starting"
            if mode.running is self.Mode.Stop:
                return self.stop()
            elif mode is self.Mode.Reset:
                return self.reset()

        # If framing is supported, make sure frame size does not exceed maximum set by descriptor
        if self.Attrs.Framing in self.attrs and self.frameSize > self.maxFrameSize:
            raise ValueError(f"Cannot start telemetry - dataframe size = {self.frameSize} samples per frame "
                             f"exceeds maximum value = {self.maxFrameSize} set by descriptor")

        log.info("{action} {telemetry} in '{mode}' mode at 1/{splitfreq} rate...".format(
                action = actionName,
                telemetry = "TM" if self.name is Null else f"TM '{self.name}'",
                mode = mode,
                splitfreq = self.divider,
        ))

        # Update device signals list if changed since last run
        if Telemetry.run.stored_signals != self.signals:
            log.debug(f"TM signals list changed - was {self.run.stored_signals}, now {self.signals}")
            log.debug("Updating TM signals on device...")
            try:
                api.setTelemetry(self.Mode.Reset)
                for signal in self.signals:
                    api.addSignal(signal)
            except (BadAckError, SerialError) as e:
                log.error(f"Failed to {actionName.lower()} TM:\n\t{e}")
                return False
            Telemetry.run.stored_signals = self.signals.copy()
            log.debug(f"Device TM signals updated - {self.signals}")

        # Finally, launch TM
        try:
            api.setTelemetry(mode, self.divider, self.frameSize or 0)
        except (BadAckError, SerialError) as e:
            log.error(f"Failed to {actionName.lower()} TM:\n\t{e}")
            return False

        # Update .mode and .status
        Telemetry.mode.slot.__set__(self, mode)
        Telemetry.status.slot.__set__(self, self.Status.OK)

        return True

    def stop(self) -> bool:
        """ Set telemetry to mode 4 """
        if self.mode in (self.Mode.Stop, self.Mode.Reset):
            log.warning(f"TM{f' {self.name}' or ''} is already stopped")

        log.info(...)

        try:
            api.setTelemetry(self.Mode.Stop)
        except (BadAckError, SerialError) as e:
            log.error(f"Failed to stop TM:\n\t{e}")
            return False

        Telemetry.mode.slot.__set__(self, self.mode.Stop)
        Telemetry.status.slot.__set__(self, self.Status.Disabled)

        return True

    def reset(self) -> bool:
        """ Set telemetry to mode 0 and clear signals list """
        if self.mode == self.Mode.Reset:
            log.warning(f"TM{f' {self.name}' or ''} is already reset")

        log.info(...)

        try:
            api.setTelemetry(self.Mode.Reset)
        except (BadAckError, SerialError) as e:
            log.error(f"Failed to reset TM - {e.__class__.__name__}:{e.args[0] if e.args else ''}")
            return False

        self.signals.clear()
        Telemetry.mode.slot.__set__(self, self.mode.Reset)
        Telemetry.status.slot.__set__(self, self.Status.Disabled)

        return True

    def add(self, signal: Signal) -> bool:
        """ Append new signal to the end of signals list """

        if not isinstance(signal, Signal):
            raise ValueError(f"Invalid signal - expected Signal instance, got '{signal.__class__.__name__}'")
        if len(self.signals) == self.maxNumSignals:
            raise RuntimeError(f"Cannot add signal - maximum of {self.maxNumSignals} signals is reached ")

        log.info(...)

        try:
            api.addSignal(signal)
        except (BadAckError, SerialError) as e:
            log.error(f"Failed to add signal '{signal.name}' to TM:\n\t{e}")
            return False

        self.signals.append(signal)

        return True

    def read(self):
        """ TODO """
        try:
            data, status = api.readTelemetry()
        except (BadAckError, SerialError) as e:
            log.error(f"Failed to read data from TM:\n\t{e}")
            return False

        print(data, status)
        # Telemetry.status.slot.__set__(self, status)
        return True


# ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————— #


if __name__ == '__main__':
    testingItem = SignalsTree

    if testingItem is Signal:

        def p(name: str, this):
            print(f"{name.upper()}: type - {type(this)}")
            print(f"{' ' * len(name)}   str - {this!s}")
            print(f"{' ' * len(name)}  repr - {this!r}")
            print()

        SampleSignal = Signal(
                n        = 0,
                name     = "SampleSignal",
                varclass = Signal.Class.Std,
                vartype  = Signal.Type.Float,
                attrs    = Signal.Attrs(15),
                parent   = -1,
                period   = 10_000,
                dimen    = Signal.Dimen.VoltPerCelsius,
                factor   = 0.25,
        )
        SampleSignal.value = 679 / 13

        SampleChild = SampleSignal.copy(name='SampleChild', parent=SampleSignal)
        SampleSignal.children = {'SampleChild': SampleChild}

        p('signal', SampleSignal)
        print('__slots__: ', SampleSignal.__slots__, '\n')
        p('sig.name', SampleSignal.name)
        p('sig.parent', SampleSignal.parent)
        # p('sig.parent.name', SampleSignal.parent.name)
        p('sig.children', SampleSignal.children)
        p('sig.signature', SampleSignal.signature)

        print('sig.__annotations__', formatDict(SampleSignal.__annotations__), '\n')
        print('sig.type', formatDict(
                {name: attr.type for name, attr in SampleSignal.__attrs__.items()}
        ), '\n')
        print('sig.type._annotation_', formatDict(
                {name: attr._annotation_ for name, attr in SampleSignal.__attrs__.items()}
        ), '\n')
        # print('iter(sig): ', tuple(SampleSignal), '\n')
        print('SampleSignal.format():', SampleSignal.format(), '\n', sep='\n')
        # CONSIDER: ▼ signal object name and signal.name may not match...
        print('child access:\n', SampleSignal.SampleChild, '\n')


    if testingItem is SignalsTree:
        from Utils import Timer
        from random import choice, sample, randint, random

        maxDepth = 5
        signalsTree = SignalsTree()

        with Timer("Generate 100 signals"):
            for k in range(100):
                name = ''.join(sample('ertuopasdfghklzxcvbnm', randint(2, 8)))
                potentialParents = (s for s in signalsTree if len(s.fullname.split('.')) < maxDepth)
                sig = Signal(
                        n=k,
                        name=f"{name}[{k}]".capitalize(),
                        varclass=Signal.Class(randint(0, 2)),
                        vartype=Signal.Type(randint(0, 7)),
                        attrs=Signal.Attrs(randint(0, 15)) & ~Signal.Attrs.Node,
                        parent=choice((*potentialParents, Signal.tree.root)).n,
                        period=randint(10, 1000) * 10,
                        dimen=Signal.Dimen(randint(0, 9)),
                        factor=choice((1, random() * 10)),
                )
                if sig.vartype.pytype == float:
                    sig.value = choice((Null, 1 / 3, 0.001, 273549.9826543, 0.0000000001, 1.0))
                elif sig.vartype.pytype == int:
                    sig.value = choice((Null, 1, 0, 1_000_000, 28))
                elif sig.vartype.pytype == bool:
                    sig.value = choice((Null, True, False))
                elif sig.vartype.pytype is str:
                    sig.value = 'SomeString'
                else:
                    assert True, "s.vartype is invalid type"
                signalsTree.append(sig)

        random_signal = signalsTree[randint(0, 99)]
        print(signalsTree)
        print()
        print(random_signal)
        print(repr(random_signal))
        print(random_signal.format())
