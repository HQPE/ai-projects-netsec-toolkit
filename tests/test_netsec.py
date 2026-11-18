import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import netsec  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "auth.log")


class TestSubnet(unittest.TestCase):
    def test_slash24(self):
        i = netsec.subnet_info("192.168.1.10/24")
        self.assertEqual(i["network"], "192.168.1.0")
        self.assertEqual(i["broadcast"], "192.168.1.255")
        self.assertEqual(i["first_host"], "192.168.1.1")
        self.assertEqual(i["last_host"], "192.168.1.254")
        self.assertEqual(i["usable_hosts"], 254)
        self.assertEqual(i["netmask"], "255.255.255.0")
        self.assertEqual(i["wildcard"], "0.0.0.255")
        self.assertEqual(i["class"], "C")
        self.assertTrue(i["private"])

    def test_slash32_and_31(self):
        self.assertEqual(netsec.subnet_info("8.8.8.8/32")["usable_hosts"], 1)
        self.assertEqual(netsec.subnet_info("10.0.0.0/31")["usable_hosts"], 2)

    def test_ipv6(self):
        i = netsec.subnet_info("2001:db8::1/64")
        self.assertEqual(i["network"], "2001:db8::")
        self.assertEqual(i["version"], 6)

    def test_split(self):
        self.assertEqual(netsec.split_subnet("10.0.0.0/24", 26),
                         ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"])
        with self.assertRaises(ValueError):
            netsec.split_subnet("10.0.0.0/24", 24)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            netsec.subnet_info("300.1.1.1/24")


class TestPorts(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(netsec.parse_ports("22, 80,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(netsec.parse_ports("common"), netsec.COMMON_PORTS)
        with self.assertRaises(ValueError):
            netsec.parse_ports("70000")

    def test_scan_localhost(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: srv.accept(), daemon=True).start()
        try:
            self.assertEqual(netsec.scan_ports("127.0.0.1", [port], 0.5), [port])
        finally:
            srv.close()


class TestLogScan(unittest.TestCase):
    def setUp(self):
        with open(SAMPLE, encoding="utf-8") as f:
            self.r = netsec.analyze_auth_log(f, threshold=5)

    def test_counts(self):
        self.assertEqual(self.r["total_failed"], 13)
        self.assertEqual(self.r["unique_ips"], 3)
        self.assertEqual(self.r["top_ips"][0], ("203.0.113.45", 6))

    def test_suspicious(self):
        self.assertEqual(set(self.r["suspicious"]), {"203.0.113.45", "198.51.100.7"})

    def test_compromise(self):
        self.assertEqual(self.r["possible_compromise"], [("root", "198.51.100.7")])

    def test_invalid_users(self):
        self.assertIn(("admin", 1), self.r["invalid_users"])


class TestHash(unittest.TestCase):
    def test_text(self):
        self.assertEqual(netsec.text_hash("abc", "sha256"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(netsec.text_hash("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")

    def test_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"abc")
        try:
            self.assertEqual(netsec.file_hash(f.name, "sha1"),
                             "a9993e364706816aba3e25717850c26c9cd0d89d")
        finally:
            os.unlink(f.name)


class TestCLI(unittest.TestCase):
    def test_subnet_cmd(self):
        self.assertEqual(netsec.main(["subnet", "10.0.0.5/8"]), 0)

    def test_logscan_alerts(self):
        self.assertEqual(netsec.main(["logscan", SAMPLE]), 1)

    def test_hash_verify(self):
        good = "900150983cd24fb0d6963f7d28e17f72"
        self.assertEqual(netsec.main(["hash", "abc", "--text", "-a", "md5", "--verify", good]), 0)
        self.assertEqual(netsec.main(["hash", "abc", "--text", "-a", "md5", "--verify", "00"]), 1)

    def test_error(self):
        self.assertEqual(netsec.main(["subnet", "bad"]), 2)


if __name__ == "__main__":
    unittest.main()
