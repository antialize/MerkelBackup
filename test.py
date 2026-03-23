#!/usr/bin/python3
# End-to-end integration test for the full backup system.
#
# 1. Builds the project in release mode.
# 2. Spins up a temporary mbackupd server on 127.0.0.1:31782 with a temp data dir.
# 3. Creates test files — small files, a large file (50 MB), a symlink to a
#    non-existent target, and duplicates (to test deduplication).
# 4. Runs backup #1, then validates and restores it, checking every file's
#    content and the symlink.
# 5. Modifies the file tree (adds one file, deletes two), runs backup #2,
#    deletes root #1, prunes unreferenced chunks, and validates the store is
#    still intact.
# 6. Restores backup #2 and verifies the file changes are reflected correctly.
# 7. Recreates a deleted file and runs backup #3, then restores and checks it —
#    specifically testing that cache invalidation works correctly (a file deleted
#    and then re-created with the same content must be re-uploaded, not skipped).
# 8. Prunes everything with --age 0 (deletes all roots and chunks), terminates
#    the server, then asserts that the remaining on-disk data is under 1 MB.
# 9. Cleans up the temp directory in a finally block regardless of failures.
import subprocess
import tempfile
import shutil
import os
import threading


def main():
    subprocess.check_call(["cargo", "build", "--release"])
    test_dir = None
    server = None
    try:
        test_dir = tempfile.mkdtemp()
        in_dir = os.path.join(test_dir, "in")

        # Write config file for the server
        server_config = os.path.join(test_dir, "mbackupd.toml")
        with open(server_config, "w") as f:
            f.write(
                """
verbosity="Info"
bind="127.0.0.1:31782"

[[users]]
name="backup"
password="hunter1"
access_level="Put"

[[users]]
name="restore"
password="hunter2"
access_level="Get"

[[users]]
name="admin"
password="hunter3"
access_level="Delete"
"""
            )
        # The server refuses to start if the config is group- or world-readable.
        os.chmod(server_config, 0o600)

        # Start the server with stderr piped so we can watch for the ready banner.
        server_data = os.path.join(test_dir, "server")
        os.mkdir(server_data)
        server = subprocess.Popen(
            [
                "target/release/mbackupd",
                "--config",
                server_config,
                "--data-dir",
                server_data,
            ],
            stderr=subprocess.PIPE,
        )

        # Drain stderr in a background thread: print every line to the terminal
        # and set an event once the startup banner appears.
        server_ready = threading.Event()
        server_stderr_eof = threading.Event()

        def drain_stderr():
            for raw in server.stderr:
                line = raw.decode(errors="replace").rstrip()
                print(f"[server] {line}", flush=True)
                if "Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N" in line:
                    server_ready.set()
            server_stderr_eof.set()

        threading.Thread(target=drain_stderr, daemon=True).start()

        # Wait until the server signals readiness or its stderr closes (crash).
        while not server_ready.is_set() and not server_stderr_eof.is_set():
            threading.Event().wait(0.05)
        if not server_ready.is_set():
            raise Exception(f"Server failed to start (exit code {server.wait()})")

        # Write configuration for the client
        client_config = os.path.join(test_dir, "mbackup.toml")
        with open(client_config, "w") as f:
            f.write(
                """
user="backup"
password="hunter1"
encryption_key="correcthorsebatterystaple"
server="http://localhost:31782"
hostname="test"
backup_dirs=["%s"]
cache_db="%s"
"""%(in_dir, os.path.join(test_dir, "cache.db"))
            )
        os.chmod(client_config, 0o600)

        # Create some test files and links
        d1 = os.path.join(in_dir, "k")
        os.makedirs(d1)
        a = os.path.join(d1, "a")
        b = os.path.join(d1, "b")
        c = os.path.join(d1, "c")
        e = os.path.join(d1, "e")
        f = os.path.join(d1, "f")
        g = os.path.join(d1, "g")
        h = os.path.join(d1, "h")
        i = os.path.join(d1, "i")
        with open(a, "w") as fi:
            fi.write("test1")
        with open(b, "w") as fi:
            fi.write("test1")
        with open(c, "w") as fi:
            fi.write("test2" * 1024 * 1024)
        with open(e, "w") as fi:
            fi.write("test3")
        with open(f, "w") as fi:
            fi.write("x" * 1024 * 1024 * 50)
        os.symlink(i, h)

        # Backup the files and validate the files
        subprocess.check_call(["target/release/mbackup", "-c", client_config, "backup"])
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "validate",
                "--full",
            ]
        )

        # Recover from backup
        r1 = os.path.join(test_dir, "r1")
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "restore",
                "1",
                "--pattern",
                "/",
                "--dest",
                r1,
            ]
        )

        # Validate backup config
        with open(os.path.join(r1, a[1:]), "r") as fi:
            if fi.read() != "test1":
                raise Exception("Bad restore 1")

        with open(os.path.join(r1, b[1:]), "r") as fi:
            if fi.read() != "test1":
                raise Exception("Bad restore 2 ")

        with open(os.path.join(r1, c[1:]), "r") as fi:
            if fi.read() != "test2" * 1024 * 1024:
                raise Exception("Bad restore 3")

        with open(os.path.join(r1, e[1:]), "r") as fi:
            if fi.read() != "test3":
                raise Exception("Bad restore 4")

        with open(os.path.join(r1, f[1:]), "r") as fi:
            if fi.read() != "x" * 1024 * 1024 * 50:
                raise Exception("Bad restore 5")

        if os.readlink(os.path.join(r1, h[1:])) != i:
            raise Exception("Bad restore link 1")

        # Modify state
        with open(g, "w") as fi:
            fi.write("test4")
        os.unlink(b)
        os.unlink(e)

        # Backup new state
        subprocess.check_call(["target/release/mbackup", "-c", client_config, "backup"])

        # Remove the old root, prune all unused items and validate the content
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "admin",
                "--password",
                "hunter3",
                "delete-root",
                "1",
            ]
        )
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "admin",
                "--password",
                "hunter3",
                "prune",
            ]
        )
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "validate"
            ]
        )

        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "validate",
                "--full",
            ]
        )

        # Recover from the second backup
        r2 = os.path.join(test_dir, "r2")
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "restore",
                "2",
                "--pattern",
                "/",
                "--dest",
                r2,
            ]
        )

        # And check the content
        with open(os.path.join(r2, a[1:]), "r") as fi:
            if fi.read() != "test1":
                raise Exception("Bad restore 6")

        if os.path.exists(os.path.join(r2, b[1:])):
            raise Exception("Bad restore 7")

        with open(os.path.join(r2, c[1:]), "r") as fi:
            if fi.read() != "test2" * 1024 * 1024:
                raise Exception("Bad restore 8")

        if os.path.exists(os.path.join(r2, e[1:])):
            raise Exception("Bad restore 9")

        with open(os.path.join(r2, f[1:]), "r") as fi:
            if fi.read() != "x" * 1024 * 1024 * 50:
                raise Exception("Bad restore 10")

        with open(os.path.join(r2, g[1:]), "r") as fi:
            if fi.read() != "test4":
                raise Exception("Bad restore 11")

        if os.readlink(os.path.join(r1, h[1:])) != i:
            raise Exception("Bad restore link 2")

        # Recreate e
        with open(e, "w") as fi:
            fi.write("test3")

        # Preform backup
        subprocess.check_call(["target/release/mbackup", "-c", client_config, "backup"])
        r3 = os.path.join(test_dir, "r3")

        # And restorm from the backup
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "restore",
                "--password",
                "hunter2",
                "restore",
                "3",
                "--pattern",
                "/",
                "--dest",
                r3,
            ]
        )

        # Check that e is as we expect,
        # the recover of e would fail here if the cache invalidation timings in the server did not work
        # as we would think the server would allready have e when performing the backup
        with open(os.path.join(r3, e[1:]), "r") as fi:
            if fi.read() != "test3":
                raise Exception("Bad restore 12")

        # Delete all the content
        subprocess.check_call(
            [
                "target/release/mbackup",
                "-c",
                client_config,
                "--user",
                "admin",
                "--password",
                "hunter3",
                "prune",
                "--age",
                "0",
            ]
        )

        # And kill the server
        if server.returncode != None:
            raise Exception("Server terminated early")
        server.terminate()
        server.wait()
        server = 0

        # Check that the prune got rid of most of the data
        usage = 0
        for dirpath, dirnames, filenames in os.walk(server_data):
            for f in filenames:
                usage += os.path.getsize(os.path.join(dirpath, f))
        if usage > 1024 * 1024:
            raise Exception("Prune did not remove enough data")
    finally:
        # Kill the server
        if server:
            server.terminate()
            server.wait()
        # And empty the test folder
        if test_dir:
            shutil.rmtree(test_dir)


if __name__ == "__main__":
    main()
