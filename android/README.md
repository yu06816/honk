# honk on Android

honk is a Linux gateway proxy: it intercepts with TC eBPF, relays in userspace,
and (upstream) requires **Linux 6.12+** because its compiled-routing path is
verified only there. Android bring-up on 6.6 is therefore an experiment, not a
supported configuration.

## What the build produces

`.github/workflows/android.yml` builds `honk-core` for
`aarch64-unknown-linux-musl` with `ebpf,rprx,clash-api,mimalloc` and embeds the
eBPF object. The result is a static binary that runs on Android without bionic
or `ld.so`.

## Device prerequisites

| Check | Command | Needed |
|---|---|---|
| Kernel | `uname -r` | 6.12+ supported; 6.6.x only with the override below |
| bpffs | `mount \| grep bpf` | mounted at `/sys/fs/bpf` |
| Kernel BTF | `ls /sys/kernel/btf/vmlinux` | present, else `HONK_VMLINUX_BTF=<file>` |
| cgroup v2 | `mount \| grep cgroup2` | the root cgroup must accept `sock_ops` |
| Root | `id` | uid 0 |
| SELinux | `getenforce` | `bpf`/`setns`/`mount` allowed for the su domain |

## Install

```sh
adb push honk-android-aarch64.tar.gz /data/local/tmp/
adb shell su -c 'cd /data/local/tmp && tar -xzf honk-android-aarch64.tar.gz'
adb shell su -c 'mkdir -p /data/adb/honk && cp /data/local/tmp/honk-android/honk-core /data/adb/honk/ && chmod 0755 /data/adb/honk/honk-core'
adb shell su -c 'cp /sdcard/config.dae /data/adb/honk/config.dae'
```

The KernelSU module in `android/ksu/` mounts bpffs (`post-fs-data.sh`) and runs
honk in a restart loop (`service.sh`). Set `HONK_ALLOW_UNSUPPORTED_KERNEL=1`
there on a 6.6 kernel.

## Bring-up order

1. **Userspace only.** `honk-core --mock-ebpf -c config.dae --data-dir /data/adb/honk`.
   Confirms config parsing, the Clash API on `127.0.0.1:9090`, and node dials
   without touching the kernel.
2. **Real datapath, everything direct.** The shipped `config.dae` routes
   `fallback: direct`. Success means the TC redirect, the `daens` namespace,
   TPROXY and the userspace relay all work. Failures here are kernel/verifier
   issues, not proxy issues.
3. **Add a node and a routing rule.** Only after step 2 passes.

## Known Android differences

- **No LAN hook.** A phone forwards nothing; `lan_interface` must stay empty.
- **`wan_interface: auto`** follows the default route and therefore moves
  between `wlan0` and `rmnet_data0`. Pin it while debugging.
- **`tproxy_mark` is fixed at `0x08000000`** (`honk-config` rejects anything
  else because the mark is compiled into the eBPF programs). If netd already
  uses those bits, the fix is a code change, not configuration.
- **`ip_forward`** is set to `1` on the host by `daens` setup.
- **Android-netns**: apps share one netns with the daemon, so WAN-only
  interception reaches them; there is no per-app netns to enter.
- **`nfqueue_enable: false`** keeps the nftables table out of the picture.

## Status

Anything below kernel 6.12 is unverified. The 6.12 floor exists because the
compiled routing program was tuned against the 6.12 verifier: instruction-state
budgets and BPF_MOD bounds differ on 6.6, so the generated program may be
rejected at load. Treat a verifier rejection as the expected failure mode.