import os
import pickle
import protocol
import time
import serial
import sys
sys.path.insert(0, "D:/GLEB/Python/")
from RFC1071 import RFC1071
import inspect


def bytewise(packet):
    return " ".join(list(map(''.join, zip(*[iter(packet.hex())]*2)))) or '<Empty>'

def main():

    s = serial.Serial(port='COM7', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_ODD, stopbits=1,
                      write_timeout=1, timeout=1)
    with s:
        d1 = '0101AABBCCDDEEFFFE889900'
        d2 = '0102'
        h1 = '5A0C0600'
        data = d2
        header = ''
        hcrc = RFC1071(header)
        fcrc = RFC1071(header+data)
        packet = bytes.fromhex(header) + hcrc.to_bytes(2, 'big') + bytes.fromhex(data) + fcrc.to_bytes(2, 'big')
        print(f"Data: {data}")
        print(f"Packet: {bytewise(packet)}")

        s.write(packet)
        res = s.read(50)
        res2 = s.read(50)
        print(f"Reply: {bytewise(res)}, ({res2})")

def testAssistPacket():

    s = serial.Serial(port='COM11', baudrate=921600,
                      bytesize=8, parity=serial.PARITY_ODD, stopbits=1,
                      write_timeout=1, timeout=5)
    with s:
        packet = s.read(100)
        print(bytewise(packet))
        print(packet[6:-2].hex())


def test_return_in_gen():
    def gen_with_return():
        for i in range(8):
            yield(f"iter {i}")
            if (i == 5):
                return f"i=={i}"
    g = gen_with_return()
    for i in range(10): print(g.__next__())


if __name__ == '__main__':
    test_return_in_gen()
    exit()



















with serial.Serial(port='COM10') as s:
    print("writing")
    s.write(b'a')
with serial.Serial(port='COM11', timeout=3) as s:
    print("reading")
    print(s.read(0))

s = serial.Serial()
s.port = "COM6"
s.baudrate = 19200

# 24 43 53 5E 24 57 48 5E
# 0x2443535E2457485E

s = serial.Serial()
s.port = "COM6"
s.baudrate = 19200
with s:
    s.write(b'$CS^')
    rep = s.read(107)
print(rep.hex().upper())
orig = "".join('2A 20 43 53 20 30 20 30 20 30 20 31 20 30 2E 32 30 30 30 30 30 20 30 2E 30 30 30 30 30 30 20 30 2E 30 30 30 30 30 30 20 32 20 30 20 32 30 30 30 20 31 36 31 36 30 20 32 37 32 31 33 20 2D 34 30 2E 30 30 30 30 30 30 20 30 2E 30 30 30 30 30 30 20 30 2E 30 30 30 30 30 30 20 33 32 35 30 30 30 0A 0A 2A 57 48 3A 20 32 38 31 0A'.split(' '))
print(rep == orig)
b = int(rep, 16).to_bytes(107,'big')
print(b)
print(b.rfind(b'16160'))
print(b.rfind(b'27213'))