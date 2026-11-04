#!/system/bin/sh
# Runs before system services start. Only prepares host resources honk needs;
# nothing here touches routing yet.

MODDIR=${0%/*}

# honk pins every eBPF map on bpffs. Android does not mount it by default.
mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

mkdir -p /data/adb/honk
chmod 0755 /data/adb/honk

# honk exits on a missing daens bind-mount directory.
mkdir -p /var/run/netns