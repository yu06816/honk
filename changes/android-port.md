Changed

- Real-backend startup accepts a kernel below the supported 6.12 floor when `HONK_ALLOW_UNSUPPORTED_KERNEL` is set to a non-zero value, for Android bring-up on 6.6.
- The instance lock falls back to `HONK_INSTANCE_LOCK` and then `<data-dir>/honk-core.lock` when `/run` does not exist, which is the case on Android's read-only root filesystem.
- A cgroup socket-address hook held by Android's netd in single-program mode degrades `pname()` rules instead of failing startup.