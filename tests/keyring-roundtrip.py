#!/usr/bin/env python3
"""Exercise GNOME Keyring recovery/restarts with disposable synthetic data."""

import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor


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
    print(f"Keyring ({env.get('PROTON_KEYRING_TEST_MODE', 'passwordless')}): {phase} passed", flush=True)


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
        password = env.get("PROTON_KEYRING_TEST_PASSWORD", "")
        keyrings = root / "data" / "keyrings"
        keyrings.mkdir(mode=0o700)
        if not password:
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
            # Only a synthetic test password, never desktop credentials.
            daemon.stdin.write(password.encode())
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

        def recover_after(make_available):
            (root / "recovery-waiting").unlink(missing_ok=True)
            with ThreadPoolExecutor(max_workers=1) as executor:
                recovery = executor.submit(run_phase, binary, "recovery", env)
                deadline = time.monotonic() + 10
                while not (root / "recovery-waiting").exists():
                    if recovery.done():
                        recovery.result()
                    if time.monotonic() > deadline:
                        raise RuntimeError("restoration did not enter waiting state")
                    time.sleep(0.05)
                result = make_available()
                try:
                    recovery.result(timeout=15)
                except BaseException:
                    if isinstance(result, subprocess.Popen):
                        stop_daemon(result)
                    raise
                return result

        def unlock_daemon():
            # Exercise the same control operation used by GNOME's PAM module.
            # --unlock starts a daemon; it does not unlock an existing one.
            # Protocol: daemon/control/gkd-control-client.c in GNOME/gnome-keyring.
            # The socket and password belong only to this disposable fixture.
            secret = password.encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(str(root / "control" / "control"))
                client.sendall(bytes([0]) + struct.pack("!III", 12 + len(secret), 1, len(secret)) + secret)
                with client.makefile("rb") as response:
                    if response.read(8) != struct.pack("!II", 8, 0):
                        raise RuntimeError("synthetic login keyring unlock failed")

        with (root / "daemon.log").open("w") as log:
            for phases in (("empty", "seed", "locked"), ("restore", "delete"), ("signed-out",)):
                if phases[0] == "restore":
                    # Restore before Secret Service exists, then start it without
                    # restarting the process waiting for its saved session.
                    daemon = recover_after(lambda: start_daemon(log))
                else:
                    daemon = start_daemon(log)
                try:
                    for phase in phases:
                        run_phase(binary, phase, env)
                        if phase == "locked" and password:
                            # Unlock a password-protected collection in place,
                            # just as desktop authentication would after login.
                            recover_after(unlock_daemon)
                except BaseException:
                    log.flush()
                    print((root / "daemon.log").read_text(), file=sys.stderr)
                    raise
                finally:
                    stop_daemon(daemon)
                files = list((root / "data" / "keyrings").glob("*.keyring"))
                if not files or not all(
                    path.read_bytes().startswith(b"[keyring]") == (not password) for path in files
                ):
                    raise RuntimeError("test did not use the expected keyring storage format")
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
    # Disable activation of host services: a missing test daemon must never
    # start another keyring with the desktop's environment/data directories.
    with tempfile.TemporaryDirectory(prefix="proton-keyring-bus-") as directory:
        config = Path(directory) / "session.conf"
        config.write_text("""<busconfig><type>session</type>
<listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
<policy context="default"><allow own="*"/><allow send_destination="*"/>
<allow receive_sender="*"/></policy></busconfig>""")
        for mode, password in (("passwordless", ""), ("encrypted", "synthetic-test-password")):
            subprocess.run(
                ["dbus-run-session", "--config-file", str(config), "--", sys.executable,
                 str(Path(__file__).resolve()), "--inside-session", binaries[0]],
                env={**env, "PROTON_KEYRING_TEST_MODE": mode,
                     "PROTON_KEYRING_TEST_PASSWORD": password},
                check=True, timeout=120,
            )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
