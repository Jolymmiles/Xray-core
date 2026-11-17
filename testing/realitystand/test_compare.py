import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from analyze import h2_startup
from compare import compare_h2, compare_handshakes, main


def stream(number, *, extensions=(0, 43), finished_length=58, startup=None):
    return {
        "stream": number,
        "ch": {"exts": extensions, "psk_identities": []},
        "server_psk_selected": False,
        "records": [{"dir": "s>c", "type": "App", "hs": ["Fin"], "len": finished_length}],
        "timing": {"client_fin": 1},
        "h2_startup": startup,
    }


class CompareTest(unittest.TestCase):
    def test_checks_every_candidate_against_reference_variants(self):
        first = stream(0)
        second = stream(1, finished_length=60)
        wrong = stream(2, finished_length=64)
        checks = compare_handshakes("full", [first, second], [second, first, wrong], "firefox")
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0][1])
        self.assertIn("stream 2", checks[0][2])

    def test_hello_and_record_shape_must_match_the_same_reference(self):
        first = stream(0)
        second = stream(1, extensions=(43, 0), finished_length=60)
        mixed = stream(2, finished_length=60)
        self.assertFalse(compare_handshakes("full", [first, second], [mixed], "firefox")[0][1])

    def test_complete_startup_cannot_hide_an_incomplete_candidate(self):
        complete = stream(0, startup=h2_startup([([31], ["SETTINGS"]), ([31], ["ACK"])]))
        checks = compare_h2([complete], [complete, stream(1)])
        self.assertTrue(any(not ok and "streams [1]" in detail for _, ok, detail in checks))

    def test_ack_in_single_record_finishes_startup(self):
        self.assertEqual(
            h2_startup([([44], []), ([31], ["SETTINGS"]), ([32], ["ACK"]), ([100], ["0"])]),
            {"before": [44], "lengths": [31, 32], "controls": ["SETTINGS", "ACK"]},
        )

    def test_ack_with_multiple_records_is_ambiguous(self):
        self.assertIsNone(h2_startup([([31], ["SETTINGS"]), ([32, 100], ["ACK", "0"])]))

    def test_settings_with_multiple_records_are_ambiguous(self):
        self.assertIsNone(h2_startup([([44, 31], ["SETTINGS"]), ([32], ["ACK"])]))

    def test_candidate_without_reference_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "ref"
            candidate = Path(directory) / "candidate"
            (reference / "chrome-nginx").mkdir(parents=True)
            (candidate / "xray-chrome-nginx").mkdir(parents=True)
            (candidate / "xray-chrome-caddy").mkdir()
            output = io.StringIO()
            with (
                patch.object(sys, "argv", ["compare.py", str(reference), str(candidate)]),
                patch("compare.compare", return_value=[("full", True, "")]),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exc,
            ):
                main()
            self.assertEqual(exc.exception.code, 1)
            self.assertIn("no chrome reference for caddy", output.getvalue())


if __name__ == "__main__":
    unittest.main()
