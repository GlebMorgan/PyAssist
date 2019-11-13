from Utils.colored_logger import LogStyle
from coloredlogs import ColoredFormatter
from humanfriendly.terminal import ansi_style, ANSI_RESET


class PacketFormatter(ColoredFormatter):

    # Defaults
    colors = dict(
         startbyte = ansi_style(color='yellow'),
           address = ansi_style(color='blue'),
            header = ansi_style(color='white'),
               ack = ansi_style(color='green'),
              data = ansi_style(color='white'),
               lrc = ansi_style(color='cyan'),
              zero = ansi_style(color='magenta'),
               rfc = ansi_style(color='red'),
        header_rfc = ansi_style(color='red'),
             reset = ANSI_RESET,
    )

    def __init__(self, colorstyle='red', *args, **kwargs):
        if colorstyle == 'console':
            self.colorstyle = LogStyle.records
        elif colorstyle == 'qt':
            self.colorstyle = LogStyle.qtRecords
        else:
            raise ValueError(f"Invalid color style: {colorstyle}")

        self.colors = dict(
             startbyte = ansi_style(**self.colorstyle['warning']),
               address = ansi_style(**self.colorstyle['info']),
                header = ansi_style(**self.colorstyle['notice']),
                   ack = ansi_style(**self.colorstyle['success']),
                  data = ansi_style(**self.colorstyle['verbose']),
                   lrc = ansi_style(**self.colorstyle['error']),
                  zero = ansi_style(**self.colorstyle['spam']),
                   rfc = ansi_style(**self.colorstyle['critical']),
            header_rfc = ansi_style(**self.colorstyle['critical']),
                 reset = ANSI_RESET,
        )

        super().__init__(*args, **kwargs)

    def format(self, record):
        msg = record.msg
        msg_start = msg.find('5A')
        prefix = msg[:msg_start]
        packet = msg[msg_start:].split(' ')

        is_reply = packet[1] == '00'
        is_zero = (int(packet[3], base=16) & 1<<7) >> 7
        core_range = (6,7) if is_reply else (6,8)
        data_range = (core_range[1], -3-is_zero)

        parts = dict(
            startbyte = packet[0],
              address = packet[1],
               header = ' '.join(packet[2:4]),
           header_rfc = ' '.join(packet[4:6]),
                  ack = ' '.join(packet[slice(*core_range)]),
                 data = ' '.join(packet[slice(*data_range)]),
                  lrc = packet[data_range[1]],
                 zero = packet[-3] if is_zero else '',
                  rfc = ' '.join(packet[-2:]),
        )

        hex_string = ' '.join(self.colors[name] + value for name, value in parts.items() if value)
        record.msg = prefix + hex_string + self.colors['reset']
        return super().format(record)

