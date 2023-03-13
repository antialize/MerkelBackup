#!/bin/sh
read -p "user: " user
read -sp "password: " password
read -sp "encryption key: " encryption_key
read -p "backupServer: " server
podman run --rm -i sadmin.scalgo.com/merkelbackuprecover "$@" <<EOF
user = "$user"
password = "$password"
encryption_key = "$encryption_key"
server = "$server"
EOF
