import contextlib
import io
import unittest
from unittest.mock import patch

import ip_reachability_checker as checker


class InterruptSemanticsTests(unittest.TestCase):
    def test_main_returns_130_on_keyboard_interrupt(self):
        stderr = io.StringIO()
        with patch.object(checker, "check_targets", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(stderr):
            code = checker.main(["127.0.0.1"])

        self.assertEqual(code, 130)
        self.assertEqual(stderr.getvalue().strip(), "Interrupted by user.")


if __name__ == "__main__":
    unittest.main()
