"""Recognize the fixed IPv4 IKEv2/UDP-ESP framing program used by MSC rules."""

PROGRAM = ((48, 0, 0, 0), (84, 0, 0, 240), (21, 0, 48, 64), (48, 0, 0, 0), (21, 0, 46, 69), (48, 0, 0, 9), (21, 0, 44, 17), (21, 0, 43, 17), (40, 0, 0, 6), (69, 41, 0, 8191), (40, 0, 0, 2), (2, 0, 0, 5), (177, 0, 0, 0), (72, 0, 0, 4), (4, 0, 0, 20), (7, 0, 0, 8), (96, 0, 0, 5), (29, 0, 33, 0), (177, 0, 0, 0), (72, 0, 0, 2), (21, 0, 12, 500), (72, 0, 0, 4), (53, 0, 28, 36), (80, 0, 0, 25), (84, 0, 0, 240), (21, 0, 25, 32), (64, 0, 0, 32), (2, 0, 0, 14), (72, 0, 0, 4), (20, 0, 0, 8), (7, 0, 0, 1), (96, 0, 0, 14), (29, 17, 18, 0), (21, 0, 17, 4500), (72, 0, 0, 4), (53, 0, 15, 16), (64, 0, 0, 8), (21, 0, 12, 0), (72, 0, 0, 4), (53, 0, 11, 40), (80, 0, 0, 29), (84, 0, 0, 240), (21, 0, 8, 32), (64, 0, 0, 36), (2, 0, 0, 11), (72, 0, 0, 4), (20, 0, 0, 12), (7, 0, 0, 14), (96, 0, 0, 11), (29, 0, 1, 0), (6, 0, 0, 262144), (6, 0, 0, 0))
BYTECODE = str(len(PROGRAM)) + "," + ",".join(" ".join(map(str, instruction)) for instruction in PROGRAM)


PROGRAM_WITH_OPTIONS = ((48, 0, 0, 0), (84, 0, 0, 240), (21, 0, 58, 64), (48, 0, 0, 0), (84, 0, 0, 240), (21, 0, 55, 64), (48, 0, 0, 0), (84, 0, 0, 15), (53, 0, 52, 5), (48, 0, 0, 9), (21, 0, 50, 17), (21, 0, 49, 17), (40, 0, 0, 6), (69, 47, 0, 8191), (40, 0, 0, 2), (2, 0, 0, 9), (177, 0, 0, 0), (72, 0, 0, 4), (2, 0, 0, 11), (48, 0, 0, 0), (84, 0, 0, 15), (36, 0, 0, 4), (7, 0, 0, 15), (96, 0, 0, 11), (12, 0, 0, 0), (7, 0, 0, 15), (96, 0, 0, 9), (29, 0, 33, 0), (177, 0, 0, 0), (72, 0, 0, 2), (21, 0, 12, 500), (72, 0, 0, 4), (53, 0, 28, 36), (80, 0, 0, 25), (84, 0, 0, 240), (21, 0, 25, 32), (64, 0, 0, 32), (2, 0, 0, 5), (72, 0, 0, 4), (20, 0, 0, 8), (7, 0, 0, 8), (96, 0, 0, 5), (29, 17, 18, 0), (21, 0, 17, 4500), (72, 0, 0, 4), (53, 0, 15, 16), (64, 0, 0, 8), (21, 0, 12, 0), (72, 0, 0, 4), (53, 0, 11, 40), (80, 0, 0, 29), (84, 0, 0, 240), (21, 0, 8, 32), (64, 0, 0, 36), (2, 0, 0, 2), (72, 0, 0, 4), (20, 0, 0, 12), (7, 0, 0, 5), (96, 0, 0, 2), (29, 0, 1, 0), (6, 0, 0, 262144), (6, 0, 0, 0))
BYTECODE_WITH_OPTIONS = str(len(PROGRAM_WITH_OPTIONS)) + "," + ",".join(" ".join(map(str, instruction)) for instruction in PROGRAM_WITH_OPTIONS)

def canonical_kind(value):
    try:
        parts = value.split(",")
        program = tuple(tuple(map(int, part.split())) for part in parts[1:])
        if int(parts[0]) != len(program):
            return None
        if program == PROGRAM:
            return "ipsecUDPFraming"
        if program == PROGRAM_WITH_OPTIONS:
            return "ipsecUDPFramingWithOptions"
    except (ValueError, TypeError):
        pass
    return None

def canonical(value):
    try:
        parts = value.split(",")
        return int(parts[0]) == len(PROGRAM) and tuple(tuple(map(int, part.split())) for part in parts[1:]) == PROGRAM
    except (ValueError, TypeError):
        return False


def payload_allowed(destination_port, payload):
    def ike(data):
        return len(data) >= 28 and data[17] >> 4 == 2 and int.from_bytes(data[24:28], "big") == len(data)
    if destination_port == 500:
        return ike(payload)
    if destination_port == 4500:
        return len(payload) >= 8 and (payload[:4] != bytes(4) or ike(payload[4:]))
    return False


def execute(packet, program=PROGRAM):
    """Evaluate the fixed program for differential tests; out-of-bounds loads reject."""
    a, x, pc = 0, 0, 0
    memory = [0] * 16
    def read(offset, length):
        if offset < 0 or offset + length > len(packet):
            raise IndexError
        return int.from_bytes(packet[offset:offset + length], "big")
    try:
        while pc < len(program):
            code, yes, no, value = program[pc]
            pc += 1
            if code == 48:
                a = read(value, 1)
            elif code == 40:
                a = read(value, 2)
            elif code in (64, 72, 80):
                a = read(x + value, {64: 4, 72: 2, 80: 1}[code])
            elif code == 84:
                a &= value
            elif code == 4:
                a = (a + value) & 0xffffffff
            elif code == 12:
                a = (a + x) & 0xffffffff
            elif code == 36:
                a = (a * value) & 0xffffffff
            elif code == 20:
                a = (a - value) & 0xffffffff
            elif code == 2:
                memory[value] = a
            elif code == 96:
                a = memory[value]
            elif code == 177:
                x = (read(value, 1) & 15) * 4
            elif code == 7:
                x = a
            elif code in (21, 29, 53, 69):
                condition = {21: a == value, 29: a == x, 53: a >= value, 69: bool(a & value)}[code]
                pc += yes if condition else no
            elif code == 6:
                return value != 0
            else:
                raise ValueError("Unsupported fixed-program instruction")
    except IndexError:
        return False
    raise ValueError("Fixed program lacks terminal verdict")
