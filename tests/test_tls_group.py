"""Synthetic decoder regressions; uses only Python's standard library."""

import csv
import io
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
EXE = Path(os.environ.get("TLS_GROUP_EXE", ROOT / "tls_group.exe"))


def block(kind, body):
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def headers(resolution=6, linktype=1):
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = struct.pack("<HHB3xHH", 9, 1, resolution, 0, 0)
    return section + block(1, struct.pack("<HHI", linktype, 0, 65535) + options)


def hello(group=0x11ED, key_size=1665):
    share = struct.pack(">HH", group, key_size) + bytes(key_size)
    extensions = struct.pack(">HHH", 43, 2, 0x0304)
    extensions += struct.pack(">HH", 51, len(share)) + share
    body = b"\x03\x03" + bytes(32) + b"\0\x13\x02\0"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def packet(payload, seq=1000, ticks=1700000000123456, linktype=1, ipv6=False):
    tcp = struct.pack(">HHIIBBHHH", 443, 50000, seq & 0xFFFFFFFF, 0, 0x50, 0x18, 65535, 0, 0)
    if ipv6:
        ip = struct.pack(">IHBB", 6 << 28, len(tcp) + len(payload), 6, 64)
        ip += bytes.fromhex("20010db8000000000000000000000001")
        ip += bytes.fromhex("20010db8000000000000000000000002")
    else:
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0,
                         bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    if linktype == 1:
        link = bytes(12) + (b"\x86\xdd" if ipv6 else b"\x08\x00")
    elif linktype == 0:
        link = struct.pack("<I", 24 if ipv6 else 2)
    else:
        link = b""
    frame = link + ip + tcp + payload
    metadata = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame))
    return block(6, metadata + frame)


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="schannel-test-")
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name) / "synthetic.pcapng"

    def run_decoder(self, capture, *args):
        self.capture.write_bytes(capture)
        return subprocess.run([str(EXE), str(self.capture), *args, "-csv"],
                              capture_output=True, text=True, check=False, timeout=10)

    def rows(self, capture, *args):
        result = self.run_decoder(capture, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return list(csv.DictReader(io.StringIO(result.stdout)))

    def test_classical_hybrid_and_link_layers(self):
        for linktype in (1, 0, 101):
            for ipv6 in (False, True):
                for group, size, name in ((0x001D, 32, "x25519"),
                                          (0x11EC, 1120, "X25519MLKEM768"),
                                          (0x11ED, 1665, "SecP384r1MLKEM1024")):
                    with self.subTest(linktype=linktype, ipv6=ipv6, group=group):
                        rows = self.rows(headers(linktype=linktype) +
                                         packet(hello(group, size), linktype=linktype, ipv6=ipv6))
                        self.assertEqual(len(rows), 1)
                        self.assertEqual(rows[0]["Group"], name)
                        self.assertEqual(rows[0]["Cipher"], "TLS_AES_256_GCM_SHA384")
                        self.assertEqual(rows[0]["Version"], "TLS1.3")

    def test_reassembly_overlap_retransmission_and_sequence_wrap(self):
        record = hello()
        for seq in (1000, 0xFFFFFFFF - 1000):
            with self.subTest(seq=seq):
                data = headers()
                data += packet(record[:1460], seq)
                data += packet(record[:1460], seq)  # Retransmitted first segment.
                data += packet(record[1200:], seq + 1200)  # Overlapping continuation.
                rows = self.rows(data)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["Group"], "SecP384r1MLKEM1024")

    def test_coalesced_records_and_incomplete_record(self):
        self.assertEqual(len(self.rows(headers() + packet(hello() + hello()))), 2)
        self.assertEqual(self.rows(headers() + packet(hello()[:1460])), [])

    def test_map_and_filter(self):
        mapping = Path(self.temp.name) / "connections.txt"
        mapping.write_text("192.0.2.1:443 192.0.2.2:50000 1234 sample.exe\n")
        capture = headers() + packet(hello())
        rows = self.rows(capture, str(mapping), "192.0.2.1")
        self.assertEqual(rows[0]["PID"], "1234")
        self.assertEqual(rows[0]["Process"], "sample.exe")
        self.assertEqual(rows[0]["Side"], "srv")
        self.assertEqual(self.rows(capture, str(mapping), "192.0.2.99"), [])

    def test_fractional_timestamp_scaling(self):
        rng = random.Random(0)
        for resolution in (0, 1, 3, 6, 9, 12, 18, 19, 0x80, 0x8A, 0xB6, 0xBF):
            denominator = (1 << (resolution & 0x7F)) if resolution & 0x80 else 10 ** resolution
            ticks = [1, denominator, denominator - 1, denominator // 2]
            ticks += [rng.randrange(1, min(2 * denominator, 1 << 64)) for _ in range(30)]
            ticks = [value for value in ticks if value > 0]
            capture = headers(resolution) + b"".join(packet(hello(0x1D, 32), ticks=t) for t in ticks)
            with self.subTest(resolution=resolution):
                rows = self.rows(capture)
                self.assertEqual(len(rows), len(ticks))
                for row, tick in zip(rows, ticks):
                    expected = (tick % denominator) * 1000 // denominator
                    self.assertEqual(int(row["Time"].split(".")[1]), expected)

    def test_invalid_timestamps_preserve_handshake(self):
        for ticks in (3_000_000_000_000, (1 << 64) - 1, 1_000_000_000_000):
            with self.subTest(ticks=ticks):
                result = self.run_decoder(headers(0) + packet(hello(), ticks=ticks))
                self.assertEqual(result.returncode, 0)
                rows = list(csv.DictReader(io.StringIO(result.stdout)))
                self.assertEqual(rows[0]["Time"], "--:--:--.---")
                self.assertEqual(rows[0]["Group"], "SecP384r1MLKEM1024")
                self.assertIn("timestamp", result.stderr.lower())

    def test_malformed_blocks_fail_explicitly(self):
        cases = [
            b"\x0a\x0d",
            struct.pack("<II", 1, 8),
            struct.pack("<II", 1, 15) + bytes(7),
            struct.pack("<II", 1, 0xFFFFFFFC),
            block(1, bytes(8))[:-4] + bytes(4),
            block(0x0A0D0D0A, bytes(4)),
            block(0x0A0D0D0A, bytes(16)),
            headers() + block(1, bytes(4)),
            headers() + block(6, bytes(4)),
            headers() + block(6, struct.pack("<IIIII", 0, 0, 0, 100, 100)),
            headers() + block(3, b""),
            headers() + block(1, bytes(8) + struct.pack("<HH", 9, 12)),
        ]
        for index, capture in enumerate(cases):
            with self.subTest(case=index):
                result = self.run_decoder(capture)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr.strip())

    def test_partial_results_do_not_make_malformed_capture_successful(self):
        result = self.run_decoder(headers() + packet(hello()) + b"\x0a\x0d")
        self.assertIn("SecP384r1MLKEM1024", result.stdout)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
