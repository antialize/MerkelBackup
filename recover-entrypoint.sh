#!/bin/sh
cat > mbackup.toml
/usr/bin/mbackup -c mbackup.toml "$@"
