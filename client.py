from __future__ import annotations

from collections.abc import Sequence
from typing import Optional, Never, overload, assert_never, Literal

import enum
import random
import copy
import time
import socket
import select
import sys
import tomllib
import itertools

# utils
def unreachable(*args, **kwargs) -> Never:
    if args or kwargs:
        raise RuntimeError("this shouldn't be reachable:\n{args=}\n{kwargs=}")
    else:
        raise RuntimeError("this should be reachable")

@overload
def assert_never_seq(rest: Never) -> Never: pass

@overload
def assert_never_seq(rest: Sequence[Never]) -> Never: pass

def assert_never_seq(rest):
    unreachable(rest)

Addr = tuple[str, int]
def timeout_recv(
    s: socket.socket,
    timeout: Optional[float] = None
) -> Optional[tuple[bytes, Addr]]:
    ok_read, _, _ = select.select([s], [], [], timeout)
    if ok_read:
        s = ok_read[0]
        msg, addr = s.recvfrom(100)
        return msg, addr
    else:
        return None
# end of utils

# ReUDP
ACK_TIMEOUT = 0.3
class TickResult(enum.Enum):
    # handshake
    GotInitAck = enum.auto()
    GotInitSyn = enum.auto()
    # messages
    GotMsg = enum.auto()
    GotAck = enum.auto()
    # meta
    Dup = enum.auto()
    Timeout = enum.auto()

HandleResult = Literal[
        TickResult.GotInitSyn,
        TickResult.GotInitAck,
        TickResult.GotMsg,
        TickResult.GotAck,
        TickResult.Dup,
    ]

def register(stats: Stats, res: HandleResult) -> None:
    match res:
        case TickResult.GotInitSyn | TickResult.GotInitAck:
            stats.meta()
        case TickResult.GotMsg | TickResult.GotAck:
            stats.got()
        case TickResult.Dup:
            stats.other()

class ReUDP:
    """ Re_liable_UDP object to use with deNAT

    Guarantees:
        - All messages will be delivered.

    But:
        - Messages may come out-of-order.
    """

    def __init__(
        self,
        s: socket.socket,
        our_id: str,
        peer_id: str,
        remote: Addr,
    ) -> None:
        # init data
        self.remote = remote
        self.our_id = our_id
        self.peer_id = peer_id

        # consts
        self.init_x = random.randint(0, 100)

        # switches
        self.s = s
        self.peer = self.first_peer_fetch()
        self.us_ok = False
        self.end = False

        # state
        self.stats = Stats()
        self.received: dict[int, str] = {}
        self.read_list: list[tuple[str, Addr]] = []

        self.last_sent_id = 0
        self.sent: dict[int, tuple[str, float, bool]] = {}

        # start a handshake
        init_syn = self.syn_msg()
        self.raw_send(init_syn)


    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.end = True
        self.tick()
        self.stats.print_results()
        # TODO: we should probably call disconnect() here as well

    def first_peer_fetch(self) -> Addr:
        return first_peer_fetch(
            self.s,
            self.our_id,
            self.peer_id,
            self.remote,
        )

    def try_to_reconnect(self) -> None:
        if self.end:
            return

        print("<> connection has failed, trying to reconnect")
        self.s = try_to_reconnect(
            self.s,
            self.our_id,
            self.peer_id,
            self.remote,
        )

    def raw_send(self, msg: bytes) -> None:
        self.s.sendto(msg, self.peer)

    def syn_msg(self) -> bytes:
        return f"init_syn:{self.init_x}".encode('utf-8')

    @staticmethod
    def init_ack_msg(init_y: int) -> bytes:
        return f"init_ack:{init_y}".encode('utf-8')

    @staticmethod
    def packed_msg(i: int, msg: str) -> bytes:
        return f"msg:{i}:{msg}".encode('utf-8')

    @staticmethod
    def ack_msg(i: int) -> bytes:
        return f"ack:{i}".encode('utf-8')

    def try_resend_lost(self) -> None:
        to_resend = []
        for (i, (_, time_sent, is_done)) in self.sent.items():
            if is_done:
                continue
            if time.monotonic() - time_sent < ACK_TIMEOUT:
                continue
            to_resend.append(i)

        for i in to_resend:
            msg, _, _ = self.sent[i]
            self.raw_send(self.packed_msg(i, msg))
            self.sent[i] = msg, time.monotonic(), False

    def handle_remote(self, payload: bytes) -> None:
        _, peer = parse_server_msg(payload)
        print(f"new peer: {peer}")
        self.peer = peer

    def handle_peer(self, payload: bytes) -> HandleResult:
        data = payload.decode('utf-8').split(":")
        match data:
            case ["init_ack", x_str] if int(x_str) == self.init_x:
                self.us_ok = True

                print("init_ack")
                return TickResult.GotInitAck
            case ["init_syn", y_str]:
                init_ack = self.init_ack_msg(int(y_str))
                self.raw_send(init_ack)

                print("init_syn")
                return TickResult.GotInitSyn
            case ["msg", msg_id_str, msg]:
                msg_id = int(msg_id_str)
                ack = self.ack_msg(msg_id)
                self.raw_send(ack)

                if msg_id not in self.received:
                    # should we store addr in received list?
                    #
                    # gosh, TCP is really lucky to only have only one
                    # connection per socket pair
                    self.received[msg_id] = msg
                    # should we even store addr in read_list?
                    self.read_list.append((msg, self.peer))

                    return TickResult.GotMsg
                else:
                    return TickResult.Dup
            case ["ack", msg_id_str]:
                msg_id = int(msg_id_str)
                match self.sent.get(msg_id, None):
                    case None:
                        # I don't think this is possible but better be safe
                        # than sorry
                        breakpoint()
                        unreachable()
                    case sent_msg, sent_time, acked:
                        if not acked:
                            self.sent[msg_id] = sent_msg, sent_time, True

                            return TickResult.GotAck
                        else:
                            return TickResult.Dup
                    case rest:
                        breakpoint()
                        assert_never_seq(rest)
            case _:
                breakpoint()
                raise RuntimeError(f"unexpected message: {payload!r}")

    def check_messages(self) -> Optional[TickResult]:
        if (res := timeout_recv(self.s, 0.15)) is not None:
            payload, addr = res
            if addr == self.remote:
                self.handle_remote(payload)
                self.stats.remote()
                return None
            elif addr == self.peer:
                ret = self.handle_peer(payload)
                register(self.stats, ret)

                match ret:
                    case TickResult.GotAck | TickResult.GotMsg:
                        return ret
                    case (
                        TickResult.GotInitSyn
                        | TickResult.GotInitAck
                        | TickResult.Dup):
                        return None
                    case rest:
                        assert_never_seq(rest)
            else:
                print(f"unknown {addr}: {payload!r}")
                self.stats.other()
                return None
        else:
            if not self.us_ok:
                init_syn = self.syn_msg()
                self.raw_send(init_syn)
            self.stats.miss()
            return None

    def tick(self, *, attempts: int = 10) -> TickResult:
        for _ in range(attempts):
            ret = self.check_message()
            self.try_resend_lost()
            if ret is not None:
                return ret
        else:
            self.try_to_reconnect()

            return TickResult.Timeout

    def get(self) -> Optional[tuple[str, Addr]]:
        if self.read_list:
            return self.read_list.pop()
        else:
            return None

    def get_blocking(self) -> tuple[str, Addr]:
        if self.read_list:
            return self.read_list.pop()
        else:
            # poll until receive the message
            while self.tick() != TickResult.GotMsg:
                pass
            res = self.get()
            if res is None:
                breakpoint()
                raise RuntimeError("got none")
            else:
                return res

    def send(self, msg: str) -> None:
        i = self.last_sent_id + 1
        self.raw_send(self.packed_msg(i, msg))
        self.sent[i] = msg, time.monotonic(), False
        self.last_send_id = i

# end of ReUDP

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

    server_msg = None
    for i in itertools.count():
        # declare that we exist
        make_peer_req(s, our_id, peer_id, remote)
        numbering = '' if i == 0 else f'#{i + 1}'
        same_line_print(i, f"<> requesting the connection {numbering}")

        # check the mailbox
        if (res := timeout_recv(s, 2)) is not None:
            msg, sender_addr = res
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
        # counters
        self.miss_counter = 0
        self.got_counter = 0
        self.remote_counter = 0
        self.meta_counter = 0
        self.other_counter = 0

        # failure counters
        self.err_clock = 0
        self.ok_clock = 0

        # start time
        self.start = time.time_ns()

        # used for periodics
        self.last = None
        self.ns = 0.0

    def reset(self):
        """ Restart timer """
        self.start = time.time_ns()

        self.last = None
        self.ns = 0.0

    def miss(self):
        self.miss_counter += 1

        self.err_clock += 1

    def got(self):
        self.got_counter += 1

        self.ok_clock += 1
        self.err_clock = 0

    def meta(self):
        self.meta_counter += 1

        self.ok_clock += 1
        self.err_clock = 0

    def remote(self):
        self.remote_counter += 1

    def other(self):
        self.other_counter += 1

    def failed_enough(self, err_limit: int) -> bool:
        if self.err_clock >= err_limit:
            self.err_clock = 0
            return True
        else:
            return False

    def good_enough(self, ok_limit: int) -> bool:
        if self.ok_clock >= ok_limit:
            self.ok_clock = 0
            return True
        else:
            return False

    def print_step(self):
        if self.last is None:
            miss = self.miss_counter
            got = self.got_counter
            other = self.other_counter
            remote = self.remote_counter
            ns_passed = time.time_ns() - self.start
        else:
            miss = self.miss_counter - self.last.miss_counter
            got = self.got_counter - self.last.got_counter
            other = self.other_counter - self.last.other_counter
            remote = self.remote_counter - self.last.remote_counter
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
        print(f"remote:\n\t{self.remote_counter}")
        print(f"meta:\n\t{self.meta_counter}")
        print(f"other:\n\t{self.other_counter}")
        ms_passed = (time.time_ns() - self.start) / (10 ** 6)
        print(f"time:\n\t{ms_passed} miliseconds")

def try_to_reconnect(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr
) -> socket.socket:
    # because both peers probably will try to reconnect
    # add some randomness to the process
    #
    # hint: the lower is the cap, the higher is the chance
    if random.random() >= 0.60:
        _, port = s.getsockname()
        s = prepare_socket(port + 1)
    # send peer request anyway though
    make_peer_req(s, our_id, peer_id, remote)
    return s

def establish_connection2(
    stats: Stats,
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr,
) -> tuple[socket.socket, Addr]:
    """ Try to establish a connection

    It's possible that portion of this protocol will leak to the next
    stage, so you'll need to handle potential syn() from the peer.
    """
    def syn_msg(rand_x: int) -> bytes:
        return f"init_syn:{rand_x}".encode('utf-8')
    def ack_msg(y: int) -> bytes:
        return f"init_ack:{y}".encode('utf-8')

    print("<> initiating connection")
    peer = first_peer_fetch(s, our_id, peer_id, remote)
    stats.reset()

    us_ok = False
    them_maybe_ok = False

    # send first syn to the peer
    init_x = random.randint(0, 100)
    s.sendto(syn_msg(init_x), peer)

    # start the main stage
    while (not us_ok) or (not them_maybe_ok):
        if stats.failed_enough(50):
            print("can't establish connection, I give up")
            sys.exit(1)

        if stats.failed_enough(10):
            s = try_to_reconnect(s, our_id, peer_id, remote)

        if (res := timeout_recv(s, 0.15)) is not None:
            msg, addr = res
            if addr != peer:
                if addr == remote:
                    _, peer = parse_server_msg(msg)
                    print(f"new peer: {peer}")
                    stats.remote()
                else:
                    stats.other()
                    # idk what to do in this case
                    # it's possible that our peer will decide to change
                    # its port and they'll get the response from remote server
                    # and send the message to us sooner than we'll get the
                    # message from the remote
                    #
                    # but I think this situation will fix itself in the end
                    breakpoint()
                continue

            data = msg.decode('utf-8').split(":")
            match data:
                case ["init_ack", x_str] if int(x_str) == init_x:
                    us_ok = True
                case ["init_syn", y_str]:
                    y = int(y_str)
                    s.sendto(ack_msg(y), peer)
                    them_maybe_ok = True
                case _:
                    breakpoint()
        else:
            stats.miss()
            if not us_ok:
                s.sendto(syn_msg(init_x), peer)

    print("<> connection is probably stable")
    return s, peer


def next_pick(turn: int) -> str:
    pick = random.choice(["paper", "rock", "scissors"])
    print(f"<*> on turn {turn} we picked: {pick}")
    return pick

class State:
    turn: int
    us_ok: bool
    they_ok: bool

    def __init__(self):
        self.turn = 0
        self.us_ok = False
        self.they_ok = False

    def is_ready(self) -> bool:
        return self.us_ok and self.they_ok

    def next_turn(self):
        self.turn += 1
        self.us_ok = False
        self.they_ok = False

def play_loop2(
    stats: Stats,
    s: socket.socket,
    our_id: str,
    peer_id: str,
    peer: Addr,
    remote: Addr,
) -> None:
    def turn_msg(turn: int, pick: str) -> bytes:
        return f"go:{turn}:{pick}".encode('utf-8')

    def ack_msg(turn: int) -> bytes:
        return f"ack:{turn}".encode('utf-8')

    state = State()
    their_picks: dict[int, str] = {}

    pick = None
    while state.turn < 10:
        pick = next_pick(state.turn)
        s.sendto(turn_msg(state.turn, pick), peer)

        while True:
            if stats.failed_enough(10):
                print("<> failure, trying to reconnect")
                s = try_to_reconnect(s, our_id, peer_id, remote)

            if (res := timeout_recv(s, 0.15)) is not None:
                msg, addr = res
                if addr != peer:
                    if addr == remote:
                        _, peer = parse_server_msg(msg)
                        print(f"new peer: {peer}")
                        stats.remote()
                    else:
                        stats.other()
                        # idk what to do in this case
                        # it's possible that our peer will decide to change
                        # its port and they'll get the response from remote server
                        # and send the message to us sooner than we'll get the
                        # message from the remote
                        #
                        # but I think this situation will fix itself in the end
                        # will add breakpoint anyway
                        breakpoint()
                    break

                data = msg.decode('utf-8').split(":")
                match data:
                    case ["ack", turn_str] if int(turn_str) == state.turn:
                        stats.got()

                        state.us_ok = True
                        if state.is_ready():
                            state.next_turn()
                            break
                    case ["go", turn_str, their_pick]:
                        print(
                            "<-> on turn {} opponent picked {}"
                              .format(turn_str, their_pick)
                        )
                        their_turn = int(turn_str)
                        s.sendto(ack_msg(their_turn), peer)

                        if their_turn not in their_picks:
                            stats.got()

                            their_picks[their_turn] = their_pick
                            if their_turn == state.turn:
                                state.they_ok = True
                                if state.is_ready():
                                    state.next_turn()
                                    break
                            else:
                                # this shouldn't be hit
                                breakpoint()
                        else:
                            stats.other()
                    case ["init_syn", y_str]:
                        y = int(y_str)
                        init_ack_msg = f"init_ack:{y}".encode('utf-8')
                        s.sendto(init_ack_msg, peer)

                        stats.other()
                    case ["init_ack", y_str]:
                        # if we can receive init_syn after the fact
                        # surefly we can expect init_ack after the fact
                        stats.other()
                    case ["ack", turn_str] if int(turn_str) < state.turn:
                        # i'm not exactly sure how this one happened,
                        # but seems like someone sent slightly more messages
                        # than needed
                        stats.other()
                    case _:
                        breakpoint()
            else:
                stats.miss()
                s.sendto(turn_msg(state.turn, pick), peer)

def main_loop2(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr,
) -> None:
    with ReUDP(s, our_id, peer_id, remote) as tunnel:
        tunnel.send("hi")
        msg, addr = tunnel.get_blocking()
        print(msg)

def main_loop(
    s: socket.socket,
    our_id: str,
    peer_id: str,
    remote: Addr,
) -> None:
    stats = Stats()
    # establish a connection
    try:
        s, peer = establish_connection2(stats, s, our_id, peer_id, remote)
        play_loop2(stats, s, our_id, peer_id, peer, remote)
    finally:
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
        main_loop2(
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
