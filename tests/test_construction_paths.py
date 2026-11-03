import contextlib
import io
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "scripts/construction/evidence"
PROFILES = ROOT / "data/extraction/networks/profiles"


class ConstructionPathTests(unittest.TestCase):
    def replay_command(self, action, explicit_checkout):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            lab = base / "lab with spaces"
            checkout = base / "separate checkout" if explicit_checkout else lab / "Twinet"
            (checkout / "bin").mkdir(parents=True)
            (checkout / "bin/twinet").write_text("test binary identity")
            argv = [str(EVIDENCE / "replay.py"), action, "samelevel", "--lab-root", str(lab)]
            if explicit_checkout:
                argv += ["--twinet-root", str(checkout)]
            if action == "collect":
                argv += ["--deployer-sha256", "a" * 64, "--snapshot-name", "fresh-capture"]
            with patch.object(sys, "argv", argv), patch.dict("os.environ", {}, clear=True), \
                    patch("os.geteuid", return_value=0), \
                    patch("subprocess.check_output", return_value="[]"), \
                    patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as execute, \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit_result:
                runpy.run_path(str(EVIDENCE / "replay.py"), run_name="__main__")
            self.assertEqual(exit_result.exception.code, 0)
            args = execute.call_args.args[0]
            self.assertEqual(execute.call_args.kwargs["cwd"], checkout)
            if action == "check":
                self.assertEqual(args[0], str(checkout / "bin/twinet"))
                self.assertEqual(Path(args[args.index("--spec") + 1]), PROFILES / "native-shared-same-level.json")
            elif action == "collect":
                self.assertEqual(Path(args[1]), EVIDENCE / "collect_native_v2.py")
                self.assertEqual(Path(args[args.index("--probe-expectations") + 1]), PROFILES / "native-same-level-probe-policy.json")
                self.assertEqual(Path(args[args.index("--output") + 1]), lab / "exports/fresh-capture")
            else:
                self.assertEqual(Path(args[1]), EVIDENCE / "native_inventory.py")
                self.assertEqual(Path(args[args.index("--root") + 1]), lab)

    def test_replay_uses_explicit_checkout_and_local_profiles(self):
        for action in ["check", "collect", "inventory"]:
            with self.subTest(action=action):
                self.replay_command(action, explicit_checkout=True)

    def test_replay_defaults_to_lab_checkout(self):
        self.replay_command("check", explicit_checkout=False)

    def test_profile_generator_preserves_native_specs_after_relocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            scripts = directory / "scripts/construction/evidence"
            scripts.mkdir(parents=True)
            profiles = directory / "data/extraction/networks/profiles"
            shutil.copy2(EVIDENCE / "make_native.py", scripts)
            shutil.copytree(PROFILES, profiles)
            names = ["native-ipsec-baseline", "native-shared-same-level", "native-shared-four-levels", "native-redundant-four-levels", "native-management-independent"]
            before = {name: json.loads((profiles / (name + ".json")).read_text()) for name in names}
            subprocess.run([sys.executable, str(scripts / "make_native.py")], cwd=temporary, check=True)
            after = {name: json.loads((profiles / (name + ".json")).read_text()) for name in names}
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
