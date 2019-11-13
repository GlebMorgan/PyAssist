from __future__ import annotations as _
import re
from enum import Enum
from functools import wraps
from typing import Union, Callable

from Transceiver import SerialError
from Utils import Logger, bytewise

from .config import CONFIG
from .errors import *


log = Logger('Core')
log.setLevel('SPAM')


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

        """ Command id (2 bytes hex string representation) """
        self.command: bytes = bytes.fromhex(command)

        """ API alias """
        self.shortcut: str = shortcut

        """ Compulsory/optional command flag """
        self.required: bool = bool(required)

        """ Expected reply data presence / length
                True - reply should contain some data apart from ACK and LRC
                False - reply should NOT contain any data except for ACK and LRC
                None - reply data check is not performed
                N - reply should contain exactly N bytes
        """
        self.expReply: Union[bool, int, None] = expReply

        """ Command category """
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
                    endIndex = pos+1
                    break
        if '\n' in docstring[methodNameStartIndex:endIndex]:
            return ' '.join(docstring[methodNameStartIndex:endIndex].split())
        else:
            return docstring[methodNameStartIndex:endIndex]


class Signal:
    Mode=type('Mode',(),{})
