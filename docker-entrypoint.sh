#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
    chown --recursive sne-sec:sne-sec /data
    exec gosu sne-sec "$@"
fi

exec "$@"
