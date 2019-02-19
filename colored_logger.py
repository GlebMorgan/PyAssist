import sys
import logging


class _AnsiColorizer:
    """
    A colorizer is an object that loosely wraps around a stream, allowing
    callers to write text to the stream in a particular color.

    Colorizer classes must implement C{supported()} and C{write(text, color)}.
    """
    _colors = dict(black='30m', red='31m', green='32m', yellow='33m',
                   blue='34m', magenta='35m', cyan='36m', white='37m',
                   brightblack = '30;1m', brightred='31;1m', brightgreen='32;1m', brightyellow='33;1m',
                   brightblue='34;1m', brightmagenta='35;1m', brightcyan='36;1m', brightwhite='37;1m')

    def __init__(self, stream):
        self.stream = stream

    @classmethod
    def supported(cls, stream=sys.stdout):
        """
        A class method that returns True if the current platform supports
        coloring terminal output using this method. Returns False otherwise.
        """
        if not stream.isatty():
            return False  # auto color only on TTYs
        try:
            import curses
        except ImportError:
            return False
        else:
            try:
                try:
                    return curses.tigetnum("colors") > 2
                except curses.error:
                    curses.setupterm()
                    return curses.tigetnum("colors") > 2
            except:
                raise
                # guess false in case of error
                return False

    def write(self, text, color):
        """
        Write the given text to the stream in the given color.

        @param text: Text to be written to the stream.

        @param color: A string label for a color. e.g. 'red', 'white'.
        """
        color = self._colors[color]
        self.stream.write(f'\x1b[{color}{text}\x1b[0m')


class ColorHandler(logging.StreamHandler):

    msg_colors = {
        logging.DEBUG: "blue",
        logging.INFO: "magenta",
        logging.WARNING: "yellow",
        logging.ERROR: "cyan",
        logging.CRITICAL: "red",
    }

    def __init__(self, stream=sys.stdout):
        super(ColorHandler, self).__init__(_AnsiColorizer(stream))

    def emit(self, record):
        color = __class__.msg_colors.get(record.levelno, "blue")
        self.stream.write(str(record.msg) + "\n", color)
