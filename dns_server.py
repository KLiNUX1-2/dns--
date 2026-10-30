
#!/usr/bin/env python3
# YUNIX CO DNS v0.2
# Local DNS filtering proxy

import socket
import struct
import ipaddress

HOST = "127.0.0.1"
PORT = 5354
UPSTREAM = ("8.8.8.8", 53)
TIMEOUT = 4


def load_domains(filename):
    domains = set()

    try:
        with open(filename, encoding="utf-8") as file:
            for raw in file:
                line = raw.strip().lower()

                if not line or line.startswith("#"):
                    continue

                if "://" in line:
                    continue

                line = line.rstrip(".")

                try:
                    ipaddress.ip_address(line)
                    continue
                except ValueError:
                    pass

                domains.add(line)

    except FileNotFoundError:
        print("Missing file:", filename)

    return domains


def load_filters():
    blocked = set()

    for filename in (
        "ads.txt",
        "track.txt",
        "malware.txt",
        "blocklist.txt"
    ):
        blocked.update(load_domains(filename))

    allowed = load_domains("allowlist.txt")

    return blocked, allowed


def read_question(packet):
    if len(packet) < 17:
        return None

    if struct.unpack("!H", packet[4:6])[0] != 1:
        return None

    pos = 12
    labels = []

    while pos < len(packet):
        length = packet[pos]
        pos += 1

        if length == 0:
            break

        if length & 0xC0 or length > 63:
            return None

        if pos + length > len(packet):
            return None

        try:
            labels.append(
                packet[pos:pos + length]
                .decode("ascii").lower()
            )
        except UnicodeDecodeError:
            return None

        pos += length

    if pos + 4 > len(packet):
        return None

    domain = ".".join(labels).rstrip(".")
    question = packet[12:pos + 4]

    return domain, question


def matches(domain, entries):
    return any(
        domain == item or
        domain.endswith("." + item)
        for item in entries
    )


def make_nxdomain(packet, question):
    query_id = packet[:2]
    request_flags = struct.unpack("!H", packet[2:4])[0]

    flags = (
        0x8000 |
        (request_flags & 0x0100) |
        0x0080 |
        0x0003
    )

    header = query_id + struct.pack(
        "!HHHHH", flags, 1, 0, 0, 0
    )

    return header + question


def main():
    blocked, allowed = load_filters()

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    server.bind((HOST, PORT))

    print("YUNIX CO DNS v0.2")
    print("Local DNS:", HOST, PORT)
    print("Blocked:", len(blocked))
    print("Allowed:", len(allowed))
    print("Upstream:", UPSTREAM)
    print("Server running...")

    while True:
        packet, client = server.recvfrom(4096)

        parsed = read_question(packet)

        if parsed is None:
            continue

        domain, question = parsed

        is_allowed = matches(domain, allowed)
        is_blocked = (
            matches(domain, blocked)
            and not is_allowed
        )

        if is_blocked:
            response = make_nxdomain(
                packet, question
            )
            print("BLOCKED:", domain)

        else:
            upstream = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            upstream.settimeout(TIMEOUT)

            try:
                upstream.sendto(packet, UPSTREAM)
                response, _ = upstream.recvfrom(4096)
                print("FORWARDED:", domain)

            except OSError as error:
                print("UPSTREAM ERROR:", error)
                continue

            finally:
                upstream.close()

        server.sendto(response, client)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("YUNIX CO DNS stopped.")
  
