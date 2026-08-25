#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

if [ "$1" = "--help" ]; then
    echo '--as-pid-1 --bind --bind-fd --bind-try --cap-drop --chdir --disable-userns --dir --dev --die-with-parent --new-session --perms --proc --remount-ro --ro-bind --ro-bind-data --ro-bind-fd --tmpfs --unshare-ipc --unshare-net --unshare-pid --unshare-user'
    exit 0
fi

for argument in "$@"; do
    if [ "$argument" = "--proc" ]; then
        echo 'procfs denied by fixture' >&2
        exit 1
    fi
done

exit 0
