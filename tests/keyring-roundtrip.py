#!/usr/bin/env python3
"""Exercise passwordless GNOME Keyring restarts with disposable synthetic data."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parent.parent
TEST = "native_backend::secret_store::tests::isolated_passwordless_keyring_restart"


def run_phase(binary, phase, env):
    result = subprocess.run(
        [binary, TEST, "--ignored", "--exact"],
        env={**env, "PROTON_KEYRING_TEST_PHASE": phase},
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print(f"Passwordless keyring: {phase} passed", flush=True)


def stop_daemon(daemon):
    if daemon.poll() is None:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=5)
            raise RuntimeError("temporary keyring did not shut down cleanly")


def inside_session(binary):
    if os.environ.get("DBUS_SESSION_BUS_ADDRESS") == os.environ.get("PROTON_KEYRING_PARENT_BUS"):
        raise RuntimeError("a private D-Bus session is required")
    with tempfile.TemporaryDirectory(prefix="proton-keyring-test-") as directory:
        root = Path(directory)
        env = dict(os.environ, PROTON_KEYRING_TEST_ROOT=directory)
        for name, subdir in (
            ("XDG_DATA_HOME", "data"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"),
            ("GNOME_KEYRING_CONTROL", "control"),
        ):
            path = root / subdir
            path.mkdir(mode=0o700)
            env[name] = str(path)
        env.pop("GNOME_KEYRING_PID", None)
        env["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=" + str(root / "no-system-bus")
        (root / "isolated-keyring-test").touch(mode=0o600)
        # Empty-password --unlock does not create a missing login collection.
        # Seed an empty GKeyFile in this disposable directory so no interactive
        # collection-creation prompt is needed.
        keyrings = root / "data" / "keyrings"
        keyrings.mkdir(mode=0o700)
        (keyrings / "login.keyring").write_text(
            "[keyring]\ndisplay-name=Test Login\nctime=0\nmtime=0\n"
            "lock-on-idle=false\nlock-after=false\n"
        )
        (keyrings / "login.keyring").chmod(0o600)
        (keyrings / "default").write_text("login\n")
        (keyrings / "default").chmod(0o600)

        def start_daemon(log):
            daemon = subprocess.Popen(
                ["gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
                 "--control-directory", env["GNOME_KEYRING_CONTROL"]],
                env=env,
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=log,
            )
            # EOF supplies an empty password to the disposable login keyring.
            daemon.stdin.close()
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if daemon.poll() is not None:
                        raise RuntimeError("temporary keyring exited during startup")
                    ready = subprocess.run(
                        ["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
                         "--object-path", "/org/freedesktop/DBus", "--method",
                         "org.freedesktop.DBus.GetNameOwner", "org.freedesktop.secrets"],
                        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
                    )
                    if ready.returncode == 0:
                        return daemon
                    time.sleep(0.05)
                raise RuntimeError("temporary keyring did not acquire its bus name")
            except BaseException:
                stop_daemon(daemon)
                raise

        with (root / "daemon.log").open("w") as log:
            for phases in (("seed",), ("restore", "delete"), ("signed-out",)):
                daemon = start_daemon(log)
                try:
                    for phase in phases:
                        run_phase(binary, phase, env)
                except BaseException:
                    log.flush()
                    print((root / "daemon.log").read_text(), file=sys.stderr)
                    raise
                finally:
                    stop_daemon(daemon)
                files = list((root / "data" / "keyrings").glob("*.keyring"))
                if not files or not all(path.read_bytes().startswith(b"[keyring]") for path in files):
                    raise RuntimeError("test did not use the passwordless GKeyFile backend")
        print("Two daemon restarts passed; shared and unrelated test credentials survived.")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inside-session":
        inside_session(sys.argv[2])
        return
    if len(sys.argv) != 1:
        raise RuntimeError("usage: python3 tests/keyring-roundtrip.py")
    for command in ("cargo", "dbus-run-session", "gnome-keyring-daemon", "gdbus"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required command is missing: {command}")
    build = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "--package", "proton-omarchy-agent",
         "--no-run", "--message-format=json"],
        cwd=REPO, stdout=subprocess.PIPE, text=True, check=True,
    )
    binaries = [
        message["executable"]
        for line in build.stdout.splitlines()
        if (message := json.loads(line)).get("reason") == "compiler-artifact"
        and message.get("executable") and message.get("profile", {}).get("test")
        and message["target"]["name"] == "proton-omarchy-agent"
    ]
    if len(binaries) != 1:
        raise RuntimeError("could not identify the agent test binary")
    env = dict(os.environ, PROTON_KEYRING_PARENT_BUS=os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""))
    subprocess.run(
        ["dbus-run-session", "--", sys.executable, str(Path(__file__).resolve()),
         "--inside-session", binaries[0]],
        env=env, check=True, timeout=120,
    )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
