from __future__ import annotations as _
import re
from enum import Enum, Flag, unique
from functools import wraps, partial
from typing import Union, Callable, ClassVar, Optional, Collection, Sequence, List, Dict, TypeVar

from Transceiver import SerialError, Transceiver
from Utils import Logger, bytewise, Dummy, auto_repr, classproperty, Null, formatDict, SingletonType
from src.Experiments.attr_tagging_concise import Classtools, TAG, const, lazy

from .config import CONFIG
from .errors import *


log = Logger('Core')
log.setLevel('SPAM')


# ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————— #

# TODO: Access children of a signal through its name (like 'Parent.Children')

# CONSIDER: struct.Struct optimization in Signal and API

# ———————————————————————————————————————————————————————————————————————————————————————————————————————————————————— #


stubs = dict(
        noValueAttr = '<NoValue>',
        noNameAttr  = '<NoName>',
        emptyAttrs  = '<NoAttrs>',
        rootSignal  = '<Root>',
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

    # CONSIDER: can I get rid of `replyDataLen`?
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
        def wrapper(this, *args, **kwargs):
            args = (this, self.command, *args)

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
            raise DataInvalidError(f"Got unexpected reply data: [{bytewise(result)}]",
                                   expected=b'', actual=result)

    @staticmethod
    def checkNoExtra(result: bytes, actual: bytes):
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


class ParamEnum(Enum):
    @property
    def index(self) -> int: return self.value

    def __index__(self): return self.value

    def __str__(self): return self.name


class ParamFlagEnum(ParamEnum, Flag):
    def __str__(self):
        if self.value == 0:
            return stubs['emptyAttrs']
        else:
            return Flag.__str__(self)[self.__class__.__name__.__len__()+1:]

    @property
    def index(self) -> int:
        # TODO: return tuple of corresponding flags indexes
        # i.e. Attrs(Telemetry|Read|Control) should return (0, 3, 5)
        raise NotImplementedError


class SignalsTree:
    """ Container for Signal objects
            Allows for efficient elements access both by integer indexes and string names
            len() returns actual number of stored Signal objects
        Usage:
            >>> signals = SignalsTree(N)  # 'N' is optional storage size for pre-allocation
            >>> signals.add(Signal('Test', ...))
            >>> signals[0]
            <Signal Test = ... at 0x...>
            >>> signals['Test']
            <Signal Test = ... at 0x...>

    """

    def __init__(self, count=None):
        self.count: int = count  # overall signals count (acquired from device)
        self.data: List[Signal] = [] if count is None else [None]*count  # (allows for access by index)
        self.names: Dict[Name, Union[Signal, List[Signal]]] = {}  # (allows for access by name)

    def __getitem__(self, key: Union[str, int]) -> Signal:
        try:
            return self.data[key]
        except TypeError:
            if not isinstance(key, str):
                raise ValueError(f"Invalid signal name - expected 'str', got '{type(key)}'")
            return self.getByName(key)

    def add(self, signal: Signal):
        if not isinstance(signal, Signal):
            raise TypeError(f"Only 'Signal' entries are allowed, got '{type(signal)}'")
        self.data[signal.n] = signal
        name = signal.name
        if name not in self.names:
            self.names[name] = signal
        elif isinstance(self.names[name], Signal):
            self.names[name] = [self.names[name], signal]
        else:
            self.names[name].append(signal)

    def getByName(self, name: str) -> Signal:
        item: Union[Signal, list] = self.names[name]
        if isinstance(item, Signal):
            return item
        else:
            raise KeyError(f"Ambiguous signal name '{name}' - "
                           f"[{', '.join(signal.fullname for signal in item)}]")

    def copy(self):
        dup = self.__class__()
        dup.data = self.data.copy()
        dup.names = self.names.copy()
        return dup

    def __str__(self, smooth=True):
        """ Render signals tree
            Raises:
                RecursionError - signals tree contains cycle references
        """

        line, fork, end, void = '│   ', '├── ', '╰── ' if smooth else '└── ', '    '
        lines = []

        def render(prefix: str, signals: Collection[Signal]):
            last = len(signals)-1
            for i, signal in enumerate(signals):
                lines.append(''.join((prefix, end if i is last else fork, str(signal))))
                if signal.children:
                    render(prefix + (void if i is last else line), signal.children.values())

        lines.append(str(Signal.root))
        render('', Signal.root.children.values())
        return '\n'.join(lines)

    def __repr__(self):
        return f"{self.__class__.__name__} ({len(self.data)} items)"

    def __len__(self):
        return self.data.__len__()

    def __contains__(self, signal):
        return signal in self.data

    def __iter__(self):
        return iter(self.data)


Name = TypeVar('Name', bound=str)  # Signal name

class Signal(metaclass=Classtools, slots=True, init=False):
    """ Signal docstring """

    # Automatically add Attrs.Node flag to node signal
    ASSIGN_NODE = True

    class Root(metaclass=SingletonType):
        """ Idle container class for top-level Signal objects
            Used in signals tree rendering
        """

        def __init__(self):
            self.name: Name = stubs['rootSignal']
            self.fullname: str = self.name
            self.children: Dict[Name, Signal] = {}

        def __str__(self):
            return self.name

        def __repr__(self):
            return auto_repr(self, 'signal')

    @unique
    class Mode(ParamEnum):
        Free = 0  # Device-driven
        Fixed = 1  # Assist-driven
        Sign = 2  # Signature-driven

    @unique
    class Class(ParamEnum):
        Var = 0
        Array = 1
        Matrix = 2

    @unique
    class Type(ParamEnum):
        String = 0, '' , str    # type 0: char[]  -> N bytes
        Bool =   1, 'B', bool   # type 1: uint_8  -> 1 byte
        Byte =   2, 'B', int    # type 2: uint_8  -> 1 byte
        Uint =   3, 'H', int    # type 3: uint_16 -> 2 bytes
        Int =    4, 'h', int    # type 4: int_16  -> 2 bytes
        Long =   5, 'i', int    # type 5: int_32  -> 4 bytes
        Ulong =  6, 'I', int    # type 6: uint_32 -> 4 bytes
        Float =  7, 'f', float  # type 7: float   -> 4 bytes

        def __new__(cls, idx: int, code: str, pyType: type):
            member = object.__new__(cls)
            member._value_ = idx
            return member

        def __init__(self, _, code: str, pytype: type):
            self.code = code
            self.pytype = pytype

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

        def __new__(cls, idx: int, sign: str):
            member = object.__new__(cls)
            member._value_ = idx
            return member

        def __init__(self, _, sign: str):
            self.sign = sign

    class Signature:
        NotImplemented

        def __repr__(self): return str(NotImplemented)

    transceiver: ClassVar[Transceiver]
    tree: ClassVar[SignalsTree] = SignalsTree()  # CONSIDER: change implementation to tree, if worthwhile
    root: ClassVar[Root] = Root()

    # Signal-defined parameters
    with TAG('variables'):
        value: Union[str, int, float, bool]  # CONSIDER: .value is None
        mode: Mode
        signature: Signature

    # Descriptor-defined parameters (immutable)
    with TAG('params') |const:
        name: Name
        varclass: Class
        vartype: Type
        attrs: Attrs
        parent: Union[Root, Signal]
        period: int
        dimen: Dimen
        factor: float

    # Assist-defined parameters
    with TAG('extra') |const:
        n: int
        fullname: str
        children: Optional[Dict[Name, Signal]]
        descriptor: str = ... |lazy('getDescriptorView')

    # Internal service parameters
    with TAG('service'):
        pass

    def __init__(self, n: int, name: Name, *,
                 varclass: Union[Class, int] = Class.Var,
                 vartype: Union[Type, int],
                 attrs: Union[Attrs, int],
                 parent: Union[Signal, int, None],
                 period: int = 10000,
                 dimen: Union[Dimen, int] = Dimen.Unitless,
                 factor: float = 1.0,
    ):

        try:
            self.n = n

            self.name = name or stubs['noNameAttr']  # CONSIDER: name.strip()?
            self.varclass = self.Class(varclass)
            self.vartype = self.Type(vartype)
            self.attrs = self.Attrs(attrs)  # TODO: Consider ASSIGN_NODE config option
            self.period = int(period)
            self.dimen = self.Dimen(dimen)
            self.factor = float(factor)

            if parent == -1 or parent is None:
                parent = self.root
            elif isinstance(parent, int):
                parent = self.tree[parent]
            elif not isinstance(parent, Signal):
                raise TypeError(f"Invalid 'parent' parameter type: "
                                f"expected 'Signal' or 'int', got {type(parent)}")
            self.parent = parent
            self.fullname = f"{parent.name}.{name}" if parent is not self.root else name

            self.value = Null
            self.mode = self.Mode.Free
            self.children = {}
            self.signature = NotImplemented

            # CONSIDER: duplicate names are not be possible if using dict
            self.parent.children[name] = self

        except (ValueError, TypeError) as e:
            raise DataInvalidError(f"Signal #{n} descriptor is invalid - {e.args[0]}")

    @classmethod
    def from_struct(cls, n: int, params: Sequence) -> Signal:
        """ Create Signal object and initialize it with `params` arguments
            Parameters are expected to be in order specified by Signal class
            No parameter type / value verification checks are performed

            Usage:
            >>> signal = Signal.from_struct((signal_n, signal_name, *descriptor_params))
        """

        this = cls.__new__(cls)
        this.n = n
        for i, name in enumerate(cls.__tags__['params']):
            setattr(this, name, params[i])  # BUG: what about to convert to appropriate type, ha?
        this.value = Null
        this.mode = cls.Mode.Free
        this.signature = NotImplemented
        return this

    def copy(self, **kwargs):  # TESTME
        new = self.__new__(self.__class__)
        for name in self.__slots__:
            value = getattr(self, name)
            if name in kwargs:
                newValue = kwargs[name]
                if isinstance(newValue, self.__class__[name].type):
                    value = newValue
                else:
                    raise TypeError(f"Invalid '{name}' attr of '{self.name}' signal: "
                                    f"expected '{type(value)}', got '{type(newValue)}'")
            setattr(new, name, value)
        return new


    @classproperty
    def attrNamesWidth(cls):
        """ Service property. Computes length (in characters) of all Signal attrs
                for aligning descriptor view elements
        """
        width = max(len(name) for name in cls.__attrs__)
        setattr(cls, 'attrNamesWidth', width)
        return width

    # service
    def getDescriptorView(self):
        lines = []
        for name in ('n', 'name', 'fullname', 'value', 'mode', 'varclass', 'vartype', 'attrs',
                     'parent', 'period', 'dimen', 'factor', 'signature'):
            lines.append(f"{name.rjust(self.attrNamesWidth)} - "
                         f"{getattr(self, name, stubs['noValueAttr'])}")
        lines.append(f"{'children'.rjust(self.attrNamesWidth)} - [{', '.join(self.children)}]")
        return '\n'.join(lines)

    def __str__(self):
        value = (round(self.value, 3)
                if self.vartype == self.Type.Float and self.value is not Null
                else self.value)
        return f"{self.name}={value}"

    def __repr__(self):
        return auto_repr(self,
            "#{n} {name} = {value}{factor}{dimen} <{type}> {{{mode}}} {attrs}".format(
                n = self.n,
                name = self.fullname if hasattr(self, 'fullname') else self.name,
                value = round(self.value, 3)
                        if self.value is not Null and self.vartype == self.Type.Float
                        else self.value,
                factor = f" ×{round(self.factor, 3)}" * (self.factor != 1 and self.value is not Null),
                dimen = self.dimen.sign * (self.dimen is not self.Dimen.Unitless and self.value is not Null),
                type = self.vartype,
                mode = self.mode.name,
                attrs = self.attrs,
            )
        )

    def __getattr__(self, name):
        fetch = partial(object.__getattribute__, self)
        try: return fetch('children')[name]
        except KeyError: raise AttributeError

    def __hash__(self):
        return hash(self.n)


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
                varclass = Signal.Class.Var,
                vartype  = Signal.Type.Float,
                attrs    = Signal.Attrs(15),
                parent   = None,
                period   = 10_000,
                dimen    = Signal.Dimen.VoltPerCelsius,
                factor   = 0.25,
        )
        SampleSignal.value = 679 / 13

        SampleChild = SampleSignal.copy(name='SampleChild', parent=SampleSignal)
        SampleSignal.children['SampleChild'] = SampleChild

        p('signal', SampleSignal)
        print('__slots__: ', SampleSignal.__slots__, '\n')
        p('sig.name', SampleSignal.name)
        p('sig.fullname', SampleSignal.fullname)
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
        print('SampleSignal.descriptor:', SampleSignal.descriptor, '\n', sep='\n')
        # CONSIDER: ▼ signal object name and signal.name may not match...
        print('child access:\n', SampleSignal.SampleChild, '\n')


    if testingItem is SignalsTree:
        from Utils import Timer
        from random import choice, sample, randint, random

        with Timer("Generate 100 signals"):
            signals = [None]
            for k in range(99):
                s = Signal(
                        n=k,
                        name=f"{''.join(sample('ertuopasdfghklxcbnm', randint(2, 8)))}".capitalize(),
                        varclass=Signal.Class(randint(0, 2)),
                        vartype=Signal.Type(randint(0, 7)),
                        attrs=Signal.Attrs(randint(0, 15)),
                        parent=choice((*signals, None)),
                        period=k * randint(10, 1000) * 10,
                        dimen=Signal.Dimen(randint(0, 9)),
                        factor=choice((1, random() * 10)),
                )
                if s.vartype.pytype == float:
                    s.value = choice((Null, 1 / 3, 0.001, 273549.9826543, 0.0000000001, 1))
                elif s.vartype.pytype == int:
                    s.value = choice((Null, 1, 0, 1_000_000, 28))
                elif s.vartype.pytype == bool:
                    s.value = choice((Null, True, False))
                elif s.vartype.pytype is str:
                    s.value = 'SomeString'
                else:
                    assert True, "s.vartype is invalid type"
                signals.append(s)

        random_signal = signals[randint(0, 99)]
        print(random_signal)
        print(repr(random_signal))
        print(random_signal.descriptor)
        print()
        print(random_signal.tree)