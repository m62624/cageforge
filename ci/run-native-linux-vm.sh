#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    echo "Usage: run-native-linux-vm.sh --image IMAGE --source-archive ARCHIVE" >&2
    exit 64
}

image=
source_archive=
while (($# > 0)); do
    case "$1" in
        --image) (($# >= 2)) || usage; image=$2; shift 2 ;;
        --source-archive) (($# >= 2)) || usage; source_archive=$2; shift 2 ;;
        *) usage ;;
    esac
done

[[ -f "$image" ]] || { echo "image is missing: $image" >&2; exit 66; }
[[ -f "$source_archive" ]] || { echo "source archive is missing: $source_archive" >&2; exit 66; }

for command in genisoimage qemu-img qemu-system-x86_64 ssh ssh-keygen; do
    command -v "$command" >/dev/null || { echo "required command is missing: $command" >&2; exit 69; }
done

[[ -c /dev/kvm ]] || { echo "CAGEFORGE_KVM_UNAVAILABLE: /dev/kvm is not available" >&2; exit 86; }

work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/cageforge-native-vm.XXXXXX")
qemu_pid=
ssh_port=$((22000 + RANDOM % 1000))
ssh_key="$work_dir/guest_ed25519"
overlay="$work_dir/guest-overlay.qcow2"
seed_iso="$work_dir/seed.iso"
source_iso="$work_dir/source.iso"
bootstrap_log="$work_dir/bootstrap-qemu.log"
test_log="$work_dir/test-qemu.log"

cleanup() {
    if [[ -n "${qemu_pid:-}" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$ssh_key"
ssh_public_key_value=$(<"$ssh_key.pub")

cat >"$work_dir/meta-data" <<EOF
instance-id: cageforge-native-vm-${GITHUB_RUN_ID:-local}
local-hostname: cageforge-native-vm
EOF

cat >"$work_dir/user-data" <<EOF
#cloud-config
package_update: true
package_upgrade: false
packages:
  - build-essential
  - ca-certificates
  - curl
  - git
  - bubblewrap
  - libcap-dev
  - openssh-server
  - pkg-config
ssh_pwauth: false
disable_root: true
ssh_authorized_keys:
  - ${ssh_public_key_value}
write_files:
  - path: /etc/cageforge-bootstrap.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      bootstrap_log=/var/log/cageforge-bootstrap.log
      : >"\$bootstrap_log"
      exec >>"\$bootstrap_log" 2>&1
      export HOME=/home/ubuntu
      export PATH=/home/ubuntu/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      echo '[cageforge] bootstrap: configuring user namespaces'
      sysctl_config=/etc/sysctl.d/99-cageforge-native-vm.conf
      printf '%s\n' 'kernel.unprivileged_userns_clone=1' >"\$sysctl_config"
      sysctl -w kernel.unprivileged_userns_clone=1
      for apparmor_sysctl in \
        kernel.apparmor_restrict_unprivileged_userns \
        kernel.apparmor_restrict_unprivileged_unconfined; do
        apparmor_sysctl_path=/proc/sys/\${apparmor_sysctl//./\\/}
        if [[ -w "\$apparmor_sysctl_path" ]]; then
          sysctl -w "\$apparmor_sysctl=0"
          printf '%s=0\n' "\$apparmor_sysctl" >>"\$sysctl_config"
        else
          echo "[cageforge] bootstrap: \$apparmor_sysctl=sysctl-unavailable"
        fi
      done
      sysctl --system
      echo '[cageforge] bootstrap: probing Bubblewrap user, PID, IPC, and network namespaces'
      echo "[cageforge] bootstrap: userns=\$(sysctl -n kernel.unprivileged_userns_clone)"
      if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
        echo "[cageforge] bootstrap: apparmor_userns=\$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)"
      else
        echo '[cageforge] bootstrap: apparmor_userns=sysctl-unavailable'
      fi
      probe_bubblewrap_namespace() {
        local namespace=\$1
        local flag=\$2
        local guidance=\$3
        shift 3
        echo "[cageforge] bootstrap: probing \$namespace namespace (\$flag)"
        if ! timeout --kill-after=5s 15s runuser -u ubuntu -- bwrap \
          --die-with-parent \
          --unshare-user \
          "\$@" \
          --ro-bind / / \
          /bin/true; then
          echo "[cageforge] bootstrap: \$namespace namespace probe failed (\$flag): \$guidance" >&2
          return 1
        fi
      }
      probe_bubblewrap_namespace user --unshare-user \
        'enable unprivileged user namespaces and permit them in the guest security policy'
      probe_bubblewrap_namespace PID --unshare-pid \
        'the guest kernel must permit CLONE_NEWPID' \
        --unshare-pid --as-pid-1
      probe_bubblewrap_namespace IPC --unshare-ipc \
        'the guest kernel must permit CLONE_NEWIPC' \
        --unshare-ipc
      probe_bubblewrap_namespace network --unshare-net \
        'the guest kernel must permit CLONE_NEWNET' \
        --unshare-net
      echo '[cageforge] bootstrap: all Bubblewrap namespace probes passed'
      echo '[cageforge] bootstrap: probing root capability removal (--cap-drop ALL)'
      if ! timeout --kill-after=5s 15s bwrap \
        --die-with-parent \
        --unshare-user \
        --unshare-pid \
        --as-pid-1 \
        --cap-drop ALL \
        --ro-bind / / \
        --proc /proc \
        /bin/sh -c \
        'awk '\''/^Cap(Inh|Prm|Eff|Bnd|Amb):/ { found++; if (\$2 != "0000000000000000") bad=1 } END { exit (found == 5 && bad == 0 ? 0 : 1) }'\'' /proc/self/status'; then
        echo '[cageforge] bootstrap: root capability removal failed (--cap-drop ALL): the guest must permit capability reduction inside user namespaces' >&2
        exit 1
      fi
      echo '[cageforge] bootstrap: root capability removal passed'
      echo '[cageforge] bootstrap: installing Rust toolchain'
      runuser -u ubuntu -- env HOME=/home/ubuntu bash -c "curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
      runuser -u ubuntu -- env HOME=/home/ubuntu PATH=/home/ubuntu/.cargo/bin:\$PATH rustup component add clippy rustfmt
      echo '[cageforge] bootstrap: completed'
      touch /var/lib/cageforge-bootstrap-complete
runcmd:
  - [bash, /etc/cageforge-bootstrap.sh]
EOF

qemu-img create -q -f qcow2 -F qcow2 -o size=16G -b "$image" "$overlay"
genisoimage -quiet -output "$seed_iso" -volid CIDATA -joliet -rock "$work_dir/user-data" "$work_dir/meta-data"
genisoimage -quiet -output "$source_iso" -volid CAGEFORGE_SOURCE -joliet -rock -graft-points "source_archive=$source_archive"

ssh_guest() {
    ssh -q -i "$ssh_key" -p "$ssh_port" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@127.0.0.1 "$@"
}

start_guest() {
    local network_mode=$1
    local log_file=$2
    local attach_source=$3
    local stderr_log="${log_file}.stderr"
    local network_spec="user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
    local source_args=()
    : >"$log_file"
    : >"$stderr_log"
    if [[ "$network_mode" == restricted ]]; then
        network_spec="user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"
    fi
    if [[ "$attach_source" == true ]]; then
        source_args=("-drive" "if=ide,media=cdrom,readonly=on,format=raw,file=${source_iso}")
    fi
    local qemu_args=(
        -machine q35,accel=kvm
        -cpu host
        -no-reboot
        -smp 2
        -m 4096
        -drive "if=virtio,format=qcow2,file=${overlay}"
        -drive "if=ide,media=cdrom,readonly=on,format=raw,file=${seed_iso}"
        "${source_args[@]}"
        -netdev "$network_spec"
        -device virtio-net-pci,netdev=net0
        -display none
        -serial "file:${log_file}"
    )
    qemu-system-x86_64 "${qemu_args[@]}" >/dev/null 2>"$stderr_log" &
    qemu_pid=$!
}

stop_guest() {
    ssh_guest 'sudo poweroff' >/dev/null 2>&1 || true
    for _ in {1..30}; do
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            wait "$qemu_pid" 2>/dev/null || true
            qemu_pid=
            return
        fi
        sleep 1
    done
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=
}

print_guest_logs() {
    local log_file=$1
    echo "--- guest serial log: ${log_file} ---" >&2
    tail -n 80 "$log_file" >&2 || true
    echo "--- qemu stderr log: ${log_file}.stderr ---" >&2
    tail -n 80 "${log_file}.stderr" >&2 || true
}

print_guest_bootstrap_diagnostics() {
    echo "--- guest bootstrap log ---" >&2
    ssh_guest 'sudo tail -n 120 /var/log/cageforge-bootstrap.log || true' >&2 || true
    echo "--- guest cloud-init status ---" >&2
    ssh_guest 'sudo cloud-init status --long || true
sudo systemctl show cloud-final.service --property=ActiveState,SubState,ExecMainStatus --no-pager || true
sudo journalctl -u cloud-final.service -n 80 --no-pager || true
sudo grep -Ei "error|fail|unexpected|exit code|traceback" /var/log/cloud-init-output.log /var/log/cloud-init.log | tail -n 80 || true
sudo dpkg --audit || true' >&2 || true
}

wait_for_ssh() {
    local log_file=$1
    for _ in {1..120}; do
        if ssh_guest true >/dev/null 2>&1; then
            return
        fi
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            print_guest_logs "$log_file"
            echo "guest stopped before SSH became available" >&2
            exit 70
        fi
        sleep 2
    done
    print_guest_logs "$log_file"
    echo "guest SSH readiness timed out" >&2
    exit 70
}

wait_for_bootstrap() {
    local log_file=$1
    echo "guest bootstrap log:" >&2
    ssh_guest 'sudo test -f /var/log/cageforge-bootstrap.log && sudo tail -n 40 /var/log/cageforge-bootstrap.log' >&2 || true
    for attempt in {1..180}; do
        if ssh_guest 'sudo test -f /var/lib/cageforge-bootstrap-complete' >/dev/null 2>&1; then
            return
        fi
        if ssh_guest 'systemctl is-failed --quiet cloud-final.service' >/dev/null 2>&1; then
            print_guest_bootstrap_diagnostics
            echo "guest bootstrap failed" >&2
            exit 70
        fi
        if (( attempt % 5 == 0 )); then
            echo "guest bootstrap still running (${attempt}/180)" >&2
            tail -n 20 "$log_file" >&2 || true
            ssh_guest 'sudo test -f /var/log/cageforge-bootstrap.log && sudo tail -n 40 /var/log/cageforge-bootstrap.log' >&2 || true
        fi
        if ! kill -0 "$qemu_pid" 2>/dev/null; then
            print_guest_logs "$log_file"
            echo "guest stopped during trusted bootstrap" >&2
            exit 70
        fi
        sleep 2
    done
    print_guest_bootstrap_diagnostics
    echo "guest bootstrap timed out" >&2
    exit 70
}

echo 'Starting trusted guest bootstrap without PR source attached.'
start_guest unrestricted "$bootstrap_log" false
wait_for_ssh "$bootstrap_log"
wait_for_bootstrap "$bootstrap_log"
stop_guest

echo 'Fetching dependencies inside the guest before network isolation.'
start_guest unrestricted "$bootstrap_log" true
wait_for_ssh "$bootstrap_log"
ssh_guest 'bash -s' <<'EOF'
set -euo pipefail
export PATH=/home/ubuntu/.cargo/bin:$PATH
source_mount=/mnt/cageforge-source
source_dir=/home/ubuntu/cageforge-source
sudo mkdir -p "$source_mount"
sudo mount -L CAGEFORGE_SOURCE -o ro "$source_mount"
rm -rf "$source_dir"
mkdir -p "$source_dir"
tar --extract --file="$source_mount/source_archive" --directory="$source_dir" --no-same-owner
root_dir=$(find "$source_dir" -mindepth 1 -maxdepth 1 -type d -print -quit)
[[ -n "$root_dir" ]]
cd "$root_dir"
cargo fetch --locked
printf '%s\n' "$root_dir" | sudo tee /var/lib/cageforge-source-root >/dev/null
sudo umount "$source_mount"
EOF
stop_guest

echo 'Running native tests inside the isolated guest.'
start_guest restricted "$test_log" true
wait_for_ssh "$test_log"
set +e
ssh_guest 'bash -s' <<'EOF'
set -euo pipefail
export PATH=/home/ubuntu/.cargo/bin:$PATH
source_mount=/mnt/cageforge-source
sudo mkdir -p "$source_mount"
sudo mount -L CAGEFORGE_SOURCE -o ro "$source_mount"
root_dir=$(sudo cat /var/lib/cageforge-source-root)
cd "$root_dir"
cargo fmt --all -- --check
cargo clippy -p cageforge-bwrap -p cageforge-core --all-targets --locked -- -D warnings

echo 'Running cageforge-linux Clippy without optional features.'
cargo clippy -p cageforge-linux --no-default-features --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests without optional features.'
cargo test -p cageforge-linux --no-default-features --locked

echo 'Running cageforge-linux Clippy with bundled-bubblewrap.'
cargo clippy -p cageforge-linux --features bundled-bubblewrap --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests with bundled-bubblewrap.'
cargo test -p cageforge-linux --features bundled-bubblewrap --locked

echo 'Running cageforge-linux Clippy with all features.'
cargo clippy -p cageforge-linux --all-features --all-targets --locked -- -D warnings
echo 'Running cageforge-linux tests with all features.'
cargo test -p cageforge-linux --all-features --locked
EOF
result=$?
set -e
stop_guest

if [[ "$result" -ne 0 ]]; then
    print_guest_logs "$test_log"
fi
exit "$result"
