"""Serve a named laboratory time source using the worker's unchanged clock."""

import argparse
import json
import socket
import struct
import time


def timestamp(nanoseconds):
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    return struct.pack("!II", seconds + 2_208_988_800, remainder * 2**32 // 1_000_000_000)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.address, 123))
    sequence = 0
    with open(args.output, "x", buffering=1) as output:
        while True:
            request, peer = server.recvfrom(4096)
            received = time.time_ns()
            if len(request) < 48 or request[0] & 7 != 3:
                continue
            response = bytearray(48)
            response[:4] = bytes([0x24, 8, request[2], 0xEC])
            response[8:12] = struct.pack("!I", 66)
            response[12:16] = b"LOCL"
            response[16:24] = timestamp(received)
            response[24:32] = request[40:48]
            response[32:40] = timestamp(received)
            sent = time.time_ns()
            response[40:48] = timestamp(sent)
            server.sendto(response, peer)
            output.write(json.dumps({
                "sequence": sequence, "source": args.source,
                "serverAddress": args.address, "clientAddress": peer[0], "clientPort": peer[1],
                "receivedUnixNs": received, "sentUnixNs": sent,
                "requestHex": request.hex(), "responseHex": response.hex(),
                "reference": "unchanged worker CLOCK_REALTIME; laboratory trust assignment is separate",
            }) + "\n")
            sequence += 1


if __name__ == "__main__":
    main()
