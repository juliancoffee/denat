from typing import Optional

import copy
import time
import socket
import select
import sys
import tomllib
import itertools

Addr = tuple[str, int]
def make_peer_req(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr,
) -> None:
    req = f"JOIN#{our_id}@{peer_id}"
    s.sendto(req.encode('utf-8'), remote)

def parse_addr(addr_string: str) -> Addr:
    host, port_string = addr_string.split(":")
    port = int(port_string)

    return host, port

def parse_server_msg(msg: bytes) -> tuple[Addr, Addr]:
    our_addr_string, peer_addr_string = msg.decode("utf-8").split(";")
    our = parse_addr(our_addr_string)
    peer = parse_addr(peer_addr_string)

    return our, peer

def same_line_print(i: int, msg: str, *args, **kwargs) -> None:
    # padding in case msg len changes
    padding = " " * 10
    if i == 0:
        print(f"{msg}" + padding, *args, **kwargs)
    else:
        to_prev_line = "\x1b[1A"
        print(f"{to_prev_line}{msg}" + padding, *args, **kwargs)

def first_peer_fetch(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr,
) -> tuple[str, int]:
    # loop to get the response (limit by 10)
    server_msg = None

    for i in itertools.count():
        # declare that we exist
        make_peer_req(s, our_id, peer_id, remote)
        numbering = '' if i == 0 else f'#{i + 1}'
        same_line_print(i, f"<> requesting the connection {numbering}")

        # check the mailbox
        ok_read, _, _ = select.select([s], [], [], 2)
        if ok_read:
            s = ok_read[0]
            msg, sender_addr = s.recvfrom(100)
            # if the message from server, we got it
            if sender_addr == remote:
                server_msg = msg
                break

    if server_msg is None:
        raise RuntimeError("couldn't get the server message")
    # parse server message
    our, peer = parse_server_msg(server_msg)

    # print response
    print(f"<> server says we are {our[0]}:{our[1]}")
    print(f"<> server says our peer is {peer[0]}:{peer[1]}")

    # finally return response
    return peer

def disconnect(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote_host: str,
    remote_port: int,
) -> None:
    req = f"EXIT#{our_id}@{peer_id}"
    s.sendto(req.encode('utf-8'), (remote_host, remote_port))
    print("<> requested exit")



def prepare_socket(port: Optional[int] = None) -> socket.socket:
    if port is None:
        try:
            port = int(sys.argv[1])
            print(f"<> using src port: {port}")
        except (ValueError, IndexError):
            port = 9_990
            print("<warn> couldn't get the src port from arguments."
                  f" Using default src port: {port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            host = "0.0.0.0"
            print(f"<> binding to {host}:{port}")
            s.bind((host, port))
            break
        except OSError as e:
            if e.errno == 48:
                print(f"<err> {port=} is taken, trying the next one")
                port += 1
            else:
                raise e
    return s


class Stats:
    def __init__(self):
        self.miss_counter = 0
        self.got_counter = 0
        self.other_counter = 0

        self.last = None
        self.start = time.time_ns()
        self.ns = 0.0

    def miss(self):
        self.miss_counter += 1

    def got(self):
        self.got_counter += 1

    def other(self):
        self.other_counter += 1

    def print_step(self):
        if self.last is None:
            miss = self.miss_counter
            got = self.got_counter
            other = self.other_counter
            ns_passed = time.time_ns() - self.start
        else:
            miss = self.miss_counter - self.last.miss_counter
            got = self.got_counter - self.last.got_counter
            other = self.other_counter - self.last.other_counter
            ns_passed = time.time_ns() - self.last.ns

        print(f"miss/got/other: {miss}/{got}/{other}")
        ms_passed = ns_passed / (10 ** 6)
        print(f"time: {ms_passed} milliseconds")

        self.last = copy.deepcopy(self)
        self.last.ns = time.time_ns()

    def print_results(self):
        print("Total stats")
        print("===========")
        print(f"miss:\n\t{self.miss_counter}")
        print(f"got:\n\t{self.got_counter}")
        print(f"other:\n\t{self.other_counter}")
        ms_passed = (time.time_ns() - self.start) / (10 ** 6)
        print(f"time:\n\t{ms_passed} miliseconds")

def main_loop(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote,
) -> None:
    print("<> initiating connection")
    peer = first_peer_fetch(s, our_id, peer_id, remote)
    print("<> starting the main loop")


    stats = Stats()
    error_clock = 0
    ok_clock = 0
    for i in range(100):
        # if missed to many requests, change the port
        if error_clock == 10:
            _, port = s.getsockname()
            s = prepare_socket(port + 1)
            peer = first_peer_fetch(s, our_id, peer_id, remote)
            error_clock = 0


        s.sendto(b"ping", peer)
        ok_read, ok_write, errs = select.select([s], [], [], 0.15)
        if ok_read:
            s = ok_read[0]
            msg, addr = s.recvfrom(100)
            if addr == peer:
                error_clock = 0
                ok_clock += 1
                stats.got()
            elif addr == remote:
                _, peer = parse_server_msg(msg)
                print(f"new peer: {peer}")
                stats.other()
            else:
                print(f"{msg!r}:{addr}")
                stats.other()
        else:
            error_clock += 1
            stats.miss()


        if (i % 10) == 0 and i != 0:
            stats.print_step()
    stats.print_results()

def main() -> None:
    try:
        with open("config.toml", "rb") as f:
            data = tomllib.load(f)

        remote_host = data["remote_host"]
        remote_port = int(data["remote_port"])
        remote = (remote_host, remote_port)

        our_id = data["our_id"]
        if len(sys.argv) >= 3:
            our_id = sys.argv[2]
            print(f"<> rewrite our_id with {our_id}")

        peer_id = data["peer_id"]
        if len(sys.argv) >= 4:
            peer_id = sys.argv[3]
            print(f"<> rewrite peer_id with {peer_id}")

    except Exception as e:
        print("couldn't read the config.toml")
        print(f"{e=}")
        sys.exit(1)

    s = prepare_socket()
    print(f"<> good, ready to connect to {remote_host}:{remote_port}")

    try:
        main_loop(
            s,
            our_id,
            peer_id,
            remote,
        )
    finally:
        disconnect(
            s,
            our_id,
            peer_id,
            remote_host,
            remote_port,
        )

if __name__ == "__main__":
    main()
