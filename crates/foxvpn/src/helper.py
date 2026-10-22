"""Fox-VPN remote helper.

The client starts this program over an SSH exec channel. It speaks FoxTunnel v1
on stdin/stdout. Logs go to stderr only. It never evaluates data from the
client as code, and it never runs a shell.
"""

import errno
import os
import select
import socket
import struct
import subprocess
import sys

MAGIC = b"FXVN"
VERSION = 1
MAX_PAYLOAD = 65535
MODE_L3 = 1
MODE_L4 = 2
FEATURE_L4 = 2
FEATURE_UDP = 8
FEATURE_L3 = 1

STDIN = sys.stdin.buffer
STDOUT = sys.stdout.buffer


def log(msg):
    sys.stderr.write("fox-vpnd: %s\n" % msg)
    sys.stderr.flush()


def write_frame(kind, payload):
    if len(payload) > MAX_PAYLOAD:
        raise RuntimeError("payload too large")
    STDOUT.write(MAGIC + bytes((VERSION, kind)) + struct.pack(">I", len(payload)) + payload)
    STDOUT.flush()


def read_available(buf):
    try:
        chunk = STDIN.read(65536)
    except BlockingIOError:
        return True
    if not chunk:
        return False
    buf[0] += chunk
    return True


def pop_frame(buf):
    if len(buf[0]) < 10:
        return None
    header = buf[0][:10]
    if header[:4] != MAGIC or header[4] != VERSION:
        raise RuntimeError("bad frame header")
    kind = header[5]
    length = struct.unpack(">I", header[6:10])[0]
    if length > MAX_PAYLOAD:
        raise RuntimeError("frame too large")
    if len(buf[0]) < 10 + length:
        return None
    payload = buf[0][10:10 + length]
    buf[0] = buf[0][10 + length:]
    return kind, payload


def parse_addr(payload, offset):
    if offset >= len(payload):
        raise RuntimeError("short address")
    alen = payload[offset]
    offset += 1
    raw = payload[offset:offset + alen]
    offset += alen
    port = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    if alen == 4:
        host = socket.inet_ntop(socket.AF_INET, raw)
    elif alen == 16:
        host = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        raise RuntimeError("bad address length")
    return host, port, offset


class Helper(object):
    def __init__(self):
        self.tcp = {}
        self.udp = {}
        self.tun = None
        self.mode = MODE_L4
        self.cleanup = []

    def close(self):
        for sock in list(self.tcp.values()) + list(self.udp.values()):
            try:
                sock.close()
            except OSError:
                pass
        for fn in reversed(self.cleanup):
            try:
                fn()
            except Exception as exc:
                log("cleanup: %s" % exc)
        if self.tun is not None:
            try:
                os.close(self.tun)
            except OSError:
                pass

    def handle(self, kind, payload):
        if kind == 1:
            mode = payload[4] if len(payload) > 4 else MODE_L4
            if mode == MODE_L3 and self.try_l3(payload):
                self.mode = MODE_L3
                write_frame(2, struct.pack(">IBH", FEATURE_L3, MODE_L3, 1280))
            else:
                if mode == MODE_L3:
                    write_frame(2, struct.pack(">IBH", FEATURE_L4 | FEATURE_UDP, 0, 1280))
                    write_frame(6, struct.pack(">H", 1) + b"L3 helper requires root and /dev/net/tun")
                    return False
                self.mode = MODE_L4
                write_frame(2, struct.pack(">IBH", FEATURE_L4 | FEATURE_UDP, MODE_L4, 1500))
            return True
        if kind == 9:
            ident = struct.unpack(">I", payload[:4])[0]
            host, port, _ = parse_addr(payload, 4)
            self.open_tcp(ident, host, port)
        elif kind == 12:
            ident = struct.unpack(">I", payload[:4])[0]
            sock = self.tcp.get(ident)
            if sock is not None:
                try:
                    sock.sendall(payload[4:])
                except OSError:
                    self.drop_tcp(ident)
        elif kind == 13:
            ident = struct.unpack(">I", payload[:4])[0]
            self.drop_tcp(ident)
        elif kind == 14:
            ident = struct.unpack(">I", payload[:4])[0]
            host, port, offset = parse_addr(payload, 4)
            self.send_udp(ident, host, port, payload[offset:])
        elif kind == 3 and self.tun is not None:
            try:
                os.write(self.tun, payload)
            except OSError as exc:
                log("tun write: %s" % exc)
        elif kind == 4 and len(payload) >= 8:
            write_frame(5, payload[:8])
        elif kind == 7:
            self.send_routes()
        return True

    def open_tcp(self, ident, host, port):
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((host, port))
        except OSError as exc:
            write_frame(11, struct.pack(">IH", ident, getattr(exc, "errno", 1) or 1))
            sock.close()
            return
        sock.setblocking(False)
        self.tcp[ident] = sock
        write_frame(10, struct.pack(">I", ident))

    def drop_tcp(self, ident):
        sock = self.tcp.pop(ident, None)
        if sock is not None:
            sock.close()
            write_frame(13, struct.pack(">I", ident))

    def send_udp(self, ident, host, port, data):
        sock = self.udp.get(ident)
        if sock is None:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                sock.connect((host, port))
            except OSError as exc:
                log("udp connect: %s" % exc)
                sock.close()
                return
            self.udp[ident] = sock
        if data:
            try:
                sock.send(data)
            except OSError as exc:
                log("udp send: %s" % exc)

    def send_routes(self):
        try:
            text = subprocess.check_output(["ip", "-4", "route", "show"], text=True, timeout=3)
        except (OSError, subprocess.SubprocessError) as exc:
            log("routes: %s" % exc)
            write_frame(8, b"")
            return
        payload = b""
        for line in text.splitlines():
            token = line.split()[0] if line.split() else ""
            if "/" not in token or token.startswith("default"):
                continue
            try:
                addr, prefix = token.split("/")
                raw = socket.inet_aton(addr)
                plen = int(prefix)
            except (OSError, ValueError):
                continue
            if 0 < plen <= 32:
                payload += raw + bytes((plen,))
        write_frame(8, payload)

    def try_l3(self, _payload):
        if os.geteuid() != 0 or not os.path.exists("/dev/net/tun"):
            return False
        try:
            self.tun = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", b"foxsrv0", 0x0001 | 0x1000)
            import fcntl
            fcntl.ioctl(self.tun, 0x400454CA, ifr)
            self.run(["ip", "addr", "add", "10.77.0.1/24", "dev", "foxsrv0"])
            self.run(["ip", "link", "set", "foxsrv0", "mtu", "1280", "up"])
            self.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.run(["sysctl", "-w", "net.ipv4.conf.foxsrv0.rp_filter=0"])
            self.run(["iptables", "-t", "nat", "-N", "FOXVPN"])
            self.run(["iptables", "-t", "nat", "-F", "FOXVPN"])
            self.run(["iptables", "-t", "nat", "-A", "FOXVPN", "-j", "MASQUERADE"])
            self.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "FOXVPN"])
            self.run(["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])
            self.cleanup.append(lambda: self.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "FOXVPN"]))
            self.cleanup.append(lambda: self.run(["iptables", "-t", "nat", "-F", "FOXVPN"]))
            self.cleanup.append(lambda: self.run(["iptables", "-t", "nat", "-X", "FOXVPN"]))
            self.cleanup.append(lambda: self.run(["ip", "link", "del", "foxsrv0"]))
            return True
        except Exception as exc:
            log("l3 setup failed: %s" % exc)
            return False

    def run(self, args):
        subprocess.run(args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def loop(self):
        import fcntl
        fd = STDIN.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        buf = [b""]
        while True:
            sockets = list(self.tcp.items()) + list(self.udp.items())
            fds = [sock for _ident, sock in sockets]
            if self.tun is not None:
                fds.append(self.tun)
            readable, _, _ = select.select([STDIN] + fds, [], [], 1.0)
            if STDIN in readable:
                if not read_available(buf):
                    return
                while True:
                    frame = pop_frame(buf)
                    if frame is None:
                        break
                    if not self.handle(frame[0], frame[1]):
                        return
            for ident, sock in list(self.tcp.items()):
                if sock in readable:
                    try:
                        data = sock.recv(16384)
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            continue
                        data = b""
                    if not data:
                        self.drop_tcp(ident)
                    else:
                        write_frame(12, struct.pack(">I", ident) + data)
            for ident, sock in list(self.udp.items()):
                if sock in readable:
                    try:
                        data = sock.recv(65535)
                    except OSError:
                        continue
                    if data:
                        write_frame(15, struct.pack(">I", ident) + data)
            if self.tun is not None and self.tun in readable:
                try:
                    packet = os.read(self.tun, 2048)
                except OSError:
                    packet = b""
                if packet:
                    write_frame(3, packet)


def main():
    helper = Helper()
    try:
        helper.loop()
    except Exception as exc:
        log("fatal: %s" % exc)
        try:
            write_frame(6, struct.pack(">H", 2) + str(exc).encode())
        except Exception:
            pass
    finally:
        helper.close()


if __name__ == "__main__":
    main()
else:
    main()
