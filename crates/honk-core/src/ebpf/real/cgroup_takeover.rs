//! Taking over root-cgroup hooks that Android's netd attached in
//! single-program mode.
//!
//! Android 15+ `netd` attaches its traffic-accounting programs with
//! `BPF_PROG_ATTACH` and no flags. A flags=0 program makes the kernel refuse
//! every later attachment on that hook, so honk's own `BPF_LINK_CREATE` fails
//! with `EPERM`. Those programs are not pinned anywhere readable, so the only
//! way to reach them is the program ID from `BPF_PROG_QUERY`.
//!
//! The takeover keeps every displaced program open in this process: detaching
//! drops the hook's reference, and an unpinned program with no other holder is
//! unloaded by the kernel. Holding the fd keeps the original alive, so
//! [`RootHookGuard::restore`] can attach it again and leave the device exactly
//! as it was found.
//!
//! Restoring must run after honk's own link is detached: a flags=0 attach is
//! refused while a multi-attach program still owns the hook.

use std::ffi::c_long;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, anyhow};
use aya_obj::generated::{
    bpf_attach_type, bpf_attr,
    bpf_cmd::{BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_GET_FD_BY_ID, BPF_PROG_QUERY},
};

use super::syscall::bpf_syscall;

/// Root-cgroup programs displaced by a takeover, held open for the process
/// lifetime so they can be attached again.
pub(super) struct RootHookGuard {
    cgroup: OwnedFd,
    displaced: Vec<(OwnedFd, bpf_attach_type)>,
}

impl RootHookGuard {
    /// Detach whatever single-program owner holds `attach_type`, keeping it
    /// alive so [`restore`](Self::restore) can put it back.
    pub(super) fn take(cgroup: &std::fs::File, attach_type: bpf_attach_type) -> Result<Self> {
        let cgroup: OwnedFd = cgroup
            .try_clone()
            .context("duplicate the cgroup fd for the hook takeover")?
            .into();
        let mut guard = Self {
            cgroup,
            displaced: Vec::new(),
        };
        guard.displace(attach_type)?;
        Ok(guard)
    }

    /// How many foreign programs this guard is holding.
    pub(super) fn displaced(&self) -> usize {
        self.displaced.len()
    }

    /// Put every displaced program back the way it was found.
    pub(super) fn restore(&mut self) -> Result<()> {
        for (fd, attach_type) in self.displaced.drain(..) {
            // A restored hook must be single-program again: that is how netd
            // left it, and flags=0 is the only mode a later netd restart can
            // replace without the same EPERM this module exists to avoid.
            prog_attach(
                self.cgroup.as_raw_fd(),
                fd.as_raw_fd(),
                attach_type,
                /* flags */ 0,
            )
            .with_context(|| format!("restoring displaced cgroup program on {attach_type:?}"))?;
        }
        Ok(())
    }

    fn displace(&mut self, attach_type: bpf_attach_type) -> Result<()> {
        loop {
            let Some(program) = query_one(self.cgroup.as_raw_fd(), attach_type)? else {
                return Ok(());
            };
            prog_detach(self.cgroup.as_raw_fd(), program, attach_type)
                .with_context(|| format!("detaching foreign cgroup program on {attach_type:?}"))?;
            // SAFETY: `program` is an fd this process owns, returned by
            // BPF_PROG_GET_FD_BY_ID and not wrapped anywhere else.
            self.displaced
                .push((unsafe { OwnedFd::from_raw_fd(program) }, attach_type));
        }
    }
}

impl Drop for RootHookGuard {
    fn drop(&mut self) {
        if self.displaced.is_empty() {
            return;
        }
        if let Err(error) = self.restore() {
            tracing::error!(
                error = %error,
                "could not restore a displaced root-cgroup program; netd traffic accounting \
                 stays detached on that hook until netd restarts"
            );
        }
    }
}

/// Duplicate the fd of the only program on `attach_type`, or `None` when the
/// hook is empty. More than one owner means the hook is not in the
/// single-program state this module knows how to restore, so it is an error
/// rather than a silent partial takeover.
fn query_one(cgroup_fd: i32, attach_type: bpf_attach_type) -> Result<Option<i32>> {
    let mut ids = [0u32; 8];
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.query.__bindgen_anon_1.target_fd = cgroup_fd as u32;
    attr.query.attach_type = attach_type as u32;
    attr.query.prog_ids = ids.as_mut_ptr() as u64;
    attr.query.__bindgen_anon_2.prog_cnt = ids.len() as u32;
    unsafe { bpf_syscall(BPF_PROG_QUERY as c_long, &mut attr) }
        .map_err(|error| anyhow!("querying cgroup attach type {attach_type:?}: errno={error}"))?;
    match attr.query.__bindgen_anon_2.prog_cnt {
        0 => Ok(None),
        1 => program_fd(ids[0]),
        other => Err(anyhow!(
            "{other} programs already own cgroup attach type {attach_type:?}; that hook is not \
             in the single-program mode this takeover can restore"
        )),
    }
}

fn program_fd(id: u32) -> Result<Option<i32>> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = id;
    match unsafe { bpf_syscall(BPF_PROG_GET_FD_BY_ID as c_long, &mut attr) } {
        Ok(fd) => Ok(Some(fd as i32)),
        // The program exited between the query and the lookup.
        Err(error) if error == libc::ENOENT as c_long => Ok(None),
        Err(error) => Err(anyhow!("opening cgroup program {id}: errno={error}")),
    }
}

fn prog_attach(cgroup_fd: i32, program_fd: i32, attach_type: bpf_attach_type, flags: u32) -> Result<()> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = cgroup_fd as u32;
    attr.__bindgen_anon_5.attach_bpf_fd = program_fd as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;
    attr.__bindgen_anon_5.attach_flags = flags;
    unsafe { bpf_syscall(BPF_PROG_ATTACH as c_long, &mut attr) }
        .map(|_| ())
        .map_err(|error| anyhow!("BPF_PROG_ATTACH: errno={error}"))
}

fn prog_detach(cgroup_fd: i32, program_fd: i32, attach_type: bpf_attach_type) -> Result<()> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_5.__bindgen_anon_1.target_fd = cgroup_fd as u32;
    attr.__bindgen_anon_5.attach_bpf_fd = program_fd as u32;
    attr.__bindgen_anon_5.attach_type = attach_type as u32;
    unsafe { bpf_syscall(BPF_PROG_DETACH as c_long, &mut attr) }
        .map(|_| ())
        .map_err(|error| anyhow!("BPF_PROG_DETACH: errno={error}"))
}
