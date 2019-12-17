import os

from Transceiver import PelengTransceiver
from Transceiver.serial_transceiver import slog
from Transceiver.errors import *
from Utils import bytewise, Logger, formatList
from Utils.colored_logger import LogRecordFormat, LogStyle, LogDateFormat, Formatters

from . import api
from .assist_packet_formatter import PacketFormatter
from .core import Command, Signal
from .errors import *


log = Logger("Cmd")
log.setConsoleHandler(Formatters.simpleColored)
log.setLevel('SPAM')

slog.setConsoleHandler(PacketFormatter(colorstyle='console',
        fmt=LogRecordFormat, datefmt=LogDateFormat, style='{',
        level_styles=LogStyle.records, field_styles=LogStyle.fields))


insidePyCharm = "PYCHARM_HOSTED" in os.environ
prompt = '' if insidePyCharm else '--> '


# map [API method shortcuts] to [method objects themselves]
commands = {command.shortcut: command for command in Command.ALL.values()}


class CommandError(AppError):
    """Application-level error, indicates invalid command signature / parameters / semantics"""


def printCommandResult(result):
    if result is None:
        log.success('OK')
    elif isinstance(result, bytes):
        log.success(bytewise(result))
    else:
        log.success(result)


def showHelp(item=None):
    apiMethods = Command.ALL.values()
    if item is None:
        # Command is just "help" --> show all command signatures
        log.verbose("Commands API:")
        for apiCommandMethod in apiMethods:
            log.info(f"{apiCommandMethod.shortcut:>5} - {Command.getCommandApi(apiCommandMethod)}")
    else:
        # Command contains explicit API command --> show signature of requested command only
        if item in (fun.__name__ for fun in apiMethods):
            # Requested API command is a full command method name
            log.verbose(f"API: {Command.getCommandApi(Command.ALL[item])}")
        elif item in (fun.shortcut for fun in apiMethods):
            # Requested API command is a shortcut
            log.verbose(f"API: {Command.getCommandApi(commands[item])}")
        else:
            # Requested API command is invalid
            raise CommandError(f"Cannot find API method name / shortcut '{item}'")


def scandev(start, end):
    oldTimeout = api.transceiver.timeout
    oldDevice = api.transceiver.deviceAddress
    api.transceiver.timeout = 0.1

    addr = []
    for i in range(int(start), int(end) + 1):
        log.info(f"Tyr addr: {i}")
        try:
            api.transceiver.deviceAddress = i
            api.checkChannel()
        except SerialReadTimeoutError:
            log.info("Fail\n")
            continue
        else:
            addr.append(i)
            log.success(f"Reply from address {i}\n")
    log.info(f"Got replies from addresses: {addr}")

    api.transceiver.timeout = oldTimeout
    api.transceiver.deviceAddress = oldDevice


def test(*args):
    if args[0] == 'scandev':
        scandev(args[1], args[2])


def apiTest():

    with api.transceiver as com:
        env = (globals(), {'api': api, 'com': com})

        for n in range(10_000):
            try:
                userinput = input(prompt).strip()

                if (userinput == ''):
                    continue

                elif userinput in ('e', 'exit'):
                    log.error("Terminated :)")
                    break

                elif userinput.startswith('-'):
                    result = api.sendCommand(userinput[1:].strip())
                    log.success(f"Reply: {bytewise(result)}")

                elif userinput.startswith('>'):
                    try:
                        log.verbose(eval(userinput[1:].strip(), *env))
                    except SyntaxError:
                        exec(userinput[1:].strip(), *env)

                elif userinput == 'flush':
                    com.reset_input_buffer()

                elif userinput == 'read':
                    reply = com.read(com.in_waiting)
                    log.verbose(f"Buffer [{len(reply)}]: {bytewise(reply)}") if (reply) else log.verbose("<Void>")

                else:
                    command, *params = userinput.split()

                    if command in ('h', 'help'):
                        showHelp(*params)

                    elif command in ('t', 'test'):
                        test(*params)

                    elif command in ('s', 'scans'):
                        createTree = not 'list' in params
                        showOutput = not 'silent' in params

                        log.verbose(f'API call: api.scanMode(tree={createTree}, showProgress=True)' +
                                    (f' <no-output>' if showOutput is False else ''))
                        with Signal.scanMode:
                            signals, failed = api.scanSignals(tree=createTree, showProgress=True)

                        if showOutput:
                            log.info(signals if createTree is True else f"Signals:\n" + formatList(signals))
                        if failed:
                            log.error("Failed to get descriptors for signals: "
                                      f"[{', '.join('#' + num for num in failed)}]")

                    elif command in commands:
                        try:
                            methodCallStr = f"api.{commands[command].__name__}({', '.join(params)})"
                            log.verbose(f'API call: {methodCallStr}')
                            printCommandResult(eval(methodCallStr, *env))
                        except TypeError as e:
                            if (f"{commands[command].__name__}()" in e.args[0]):
                                log.error(e)
                            else: raise
                        except SyntaxError:
                            raise CommandError("Command syntax is incorrect. "
                                               "Enter command shortcut followed by parameters separated with spaces. "
                                               "Remember not to put spaces within single parameter :)")

                    else:
                        raise CommandError("Wrong command")

            except SerialReadTimeoutError: log.error('No reply')
            except (AppError, DeviceError, SerialError, NotImplementedError) as e: log.error(e)
            except Exception as e: log.error(e, traceback=True)


if __name__ == '__main__':

    api.transceiver = PelengTransceiver(device=12, port='COM2')


    apiTest()