raw = []
with open("i2c.csv") as ff:
    for l in ff.readlines()[1:]:
        ll = l.split(",")
        raw.append((ll[0], ll[2],))


def toBits(hexStr):
    n = int(hexStr, 16)
    return [(n >> (7 - i)) & 1 for i in range(0, 8)]


def toInt(bitList):
    return int("".join([str(x) for x in bitList]), 2)


def getBit(n, x):
    return (n >> x) & 1


def reverseBits(n):
    return int(bin(n)[2:].zfill(8)[::-1], 2)


class I2cPacket:
    # Packet bits to I/O pin mapping
    # RS | RW | E | BL | D7 | D6 | D5 | D4
    def __init__(self, timestamp, writeAddr, bits):
        self.timestamp = timestamp
        self.writeAddr = writeAddr
        self.raw = bits
        self.RS = bits[-1] == 1
        self.RW = bits[-2] == 1
        self.E = bits[-3] == 1
        self.BL = bits[-4] == 1
        self.data = toInt(bits[0:4])

    def toString(self):
        pins = []
        pins.append("RS" if self.RS else "  ")
        pins.append("RW" if self.RW else "  ")
        pins.append(" E" if self.E else "  ")
        pins.append("BL" if self.BL else "  ")

        return "{} ({})\t[{}]\t{}".format(
            self.timestamp, self.writeAddr, "|".join(pins), bin(self.data)[2:].zfill(4)
        )


packets = []
# For writeup
bits = []

# Current I2C address writing to
writeAddr = ""
for l in raw:

    t, d = l
    # Prepare write to I2C device
    if d.startswith("Setup Write"):
        writeAddr = d[16:20]
    # Instructions to LCD1602
    else:
        value = int(d[0:4], 16)
        bits.append("{} ({})\t{}".format(t, writeAddr, bin(value)[2:].zfill(8)))

        packet = I2cPacket(t, writeAddr, toBits(d[0:4]))
        if not packet.E:
            # E pin not high
            continue

        packets.append(packet)

with open("packets.txt", "w") as ff:
    ff.writelines(["\n".join([p.toString() for p in packets])])
with open("bits.txt", "w") as ff:
    ff.writelines(["\n".join([b for b in bits])])

# Initialization process
# Sends (0x03 << 4) three times then change to 4 bit with (0x02 << 4)
packets = packets[4:]

# Parse packets in 4-bit interface
instructions = []
parsedff = open("parsed.txt", "w")

for i in range(0, len(packets), 2):
    p1, p2 = packets[i], packets[i + 1]
    assert p1.RS == p2.RS and p1.RW == p2.RW and p1.E == p2.E and p1.BL == p2.BL

    data = p1.data << 4 | p2.data
    if p1.RS:
        instructions.append(("READ " if p1.RW else "WRITE ") + chr(data))
        if not p1.RW:
            parsedff.write(chr(data))
    elif getBit(data, 7):
        addr = data & (1 << 8 - 1)
        if addr == 0x80:
            # Newline on display
            parsedff.write("\n")
        instructions.append("SET DDRAM = " + hex(addr))
    elif getBit(data, 6):
        addr = data & (1 << 7 - 1)
        instructions.append("SET CGRAM = " + hex(addr))
    elif getBit(data, 5):
        DL, N, F = getBit(data, 4), getBit(data, 3), getBit(data, 2)
        instructions.append(
            "FN SET = {} / {} / {}".format(
                "8 BIT" if DL else "4 BIT",
                "2 LINE" if N else "1 LINE",
                "5x10" if F else "5x8",
            )
        )
    elif getBit(data, 4):
        SC, RL = getBit(data, 3), getBit(data, 2)
        instructions.append(
            "SHIFT SET = {} {}".format(
                "SCREEN" if SC else "CURSOR", "RIGHT" if RL else "LEFT"
            )
        )
    elif getBit(data, 3):
        D, C, B = getBit(data, 2), getBit(data, 1), getBit(data, 0)
        instructions.append(
            "DISPLAY {} / CURSOR {} / BLINK {}".format(
                "ON" if D else "OFF", "ON" if C else "OFF", "ON" if B else "OFF",
            )
        )
    elif getBit(data, 2):
        ID, S = getBit(data, 1), getBit(data, 0)
        instructions.append(
            "ON R/W {} {}".format(
                "INC" if ID else "DEC", "+ DISPLAY SHIFT" if S else ""
            )
        )
    elif getBit(data, 1):
        instructions.append("RET HOME")
    elif getBit(data, 0):
        instructions.append("CLEAR DISPLAY")
        parsedff.write("\n================\n")

parsedff.close()
with open("instructions.txt", "w") as ff:
    ff.writelines("\n".join(instructions))
