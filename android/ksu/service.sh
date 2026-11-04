#!/system/bin/sh
# Starts honk-core after boot and keeps it alive.
#
# Kernel < 6.12 is unsupported upstream; this build only runs there with
# HONK_ALLOW_UNSUPPORTED_KERNEL=1 and is unverified.

MODDIR=${0%/*}
HONK_DIR=/data/adb/honk
BIN=$HONK_DIR/honk-core
CONF=$HONK_DIR/config.dae
LOG=$HONK_DIR/run.log

until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 2
done
sleep 5

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

[ -x "$BIN" ] || { echo "honk-core not found at $BIN" >>"$LOG"; exit 1; }

# SELinux: the su/KernelSU domain needs bpf, setns and mount permissions.
# While bringing the datapath up, permissive mode isolates SELinux from
# kernel/verifier failures. Replace with sepolicy rules once it works.
# setenforce 0

export HONK_ALLOW_UNSUPPORTED_KERNEL=1

while true; do
    "$BIN" --config "$CONF" --data-dir "$HONK_DIR" --bpf-pin-root /sys/fs/bpf >>"$LOG" 2>&1
    rc=$?
    echo "honk-core exited rc=$rc, restarting in 10s" >>"$LOG"
    sleep 10
done