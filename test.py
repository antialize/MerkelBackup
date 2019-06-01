#!/usr/bin/python3
import subprocess
import tempfile
import shutil
import os
import time


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

        # Start the server
        server_data = os.path.join(test_dir, "server")
        os.mkdir(server_data)
        server = subprocess.Popen(
            [
                "target/release/mbackupd",
                "--config",
                server_config,
                "--data-dir",
                server_data,
            ]
        )

        # Write configuration for the client
        client_config = os.path.join(test_dir, "mbackup.toml")
        with open(client_config, "w") as f:
            f.write(
                f"""
user="backup"
password="hunter1"
encryption_key="correcthorsebatterystaple"
server="http://localhost:31782"
hostname="test"
backup_dirs=["{in_dir}"]
cache_db="{os.path.join(test_dir, "cache.db")}"
"""
            )

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
        # os.symlink(h, i) TODO

        # Backup the files and validate the files
        time.sleep(0.5)
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

        # TODO symlink

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

        # TODO symlink

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
