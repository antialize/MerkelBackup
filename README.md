# MerkelBackup

[![Travis Build Status](https://travis-ci.org/antialize/MerkelBackup.svg?branch=master)](https://travis-ci.org/antialize/MerkelBackup)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)


MerkelBackup is a simple backup solution based on merkel trees. MerkelBackup backups are:
* Incremental: Files are split into chunks of 64MB and only changed chunks are stored.
* Encrypted: The data on the server is encrypted using chacha20, so that a compromise of the backup server does not leak the data.
* Deduplicated: File chunks and folders are stored by hash value in the merkel tree on the server, so duplicate files even from different servers are only stored once.
* Checksumed: File chenks and folders are stored in a merkel tree by hash value on the server, and the integrity of the data is validated on restore.

MerkelBackup consists of a server mbackupd and a client mbackup. The client connects to the server over a REST api.

# Installing
To install the server and client extract the source and run
```sh
cargo build --release
cargo install --path . --root /usr
```

# Running the server
First create a config file in /etc/mbackupd.toml with content like below:
```toml
bind = "0.0.0.0:3321"
data_dir = "/var/mbackup"
ssl_cert = "/etc/cert.pxf"
ssl_key = "hunter1"

[[users]]
name = "backup"
password = "hunter2"
access_level = "Put"

[[users]]
name = "recover"
password = "hunter3"
access_level = "Get"

[[users]]
name = "admin"
password = "hunter4"
access_level = "Delete"
```

Make sure that `/etc/cert.pxf` is a valid DER-formatted PKCS #12 archive for the host the backup server is running on,
and that `ssl_key` is the key the certificiate is encrypted with. To generate a .pfx from an openssl certificate run
```sh
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
```

Also make sure that the `/var/mbackup` directory exists and is writable by whatever user you want the server to run as.

Finally you can run the backup server as
```sh
mbackup -c /etc/mbackupd.toml
```

**Note** that the server does not demonize, if you want that create a systemd service file or run the server through docker. Also note that the server uses simple http basic auth, and that the passwords are stored in plain text, so use long auto generated passwords like the output from
``sh 
pwgen -n 30
``

# Running the client
First create a config file in /etc/mbackup.toml with content like below:
```toml
user = "backup"
password = "hunter2"
encryption_key = "MySecretEncryptionKey"
server = "https://backup.example.com"
backup_dirs = [
    "/home/importantuser",
    "/var/importantdata",
]
cache_db = "/var/cache/mbackup/cache.db"
```
Make sure that the `/var/cache/mbackup/` dir exists and is writable by whatever user the backup client should be run as.

To perform a backup run
```sh
mbackup backup
```

To recover from a backup run
```sh
mbackup -c /etc/mbackup.toml --user recover --password hunter3 roots
```
To get a list of backup roots, find the `id` of the root you want to restore from (say 42) and run
```sh
mbackup -c /etc/mbackup.toml --user recover --password hunter3 restore 42 -p /home/importantuser/mydir
```

To remove old backups and free up space run
```sh
mbackup -c /etc/mbackup.toml --user admin --password hunter4 prune --age 90
```
This will remove all backups older than 90 days.

To validate the integrety of the backedup date run
```sh
mbackup -c /etc/mbackup.toml --user recover --password hunter3 validate --full
```

# Stability
This software has has not been tested extensively so use it at your own peril.
