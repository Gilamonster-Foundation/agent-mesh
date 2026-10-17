//! Process hardening, before any key exists: no core dumps, no ptrace by
//! other processes where the OS has the knob.

use crate::SessionError;
use rustix::process::{getrlimit, setrlimit, Resource};

/// What to do when memory cannot be locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Refuse to start (the default).
    Locked,
    /// Carry on with the key swappable. Loud opt-out.
    AllowUnlocked,
}

/// What `harden` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// `RLIMIT_CORE` is now zero.
    pub core_limit_zero: bool,
    /// The process is marked non-dumpable (Linux) or denies attach (macOS).
    pub non_dumpable: bool,
}

/// Turn core dumps off. Both steps are required: a failure is an error.
///
/// # Errors
/// The OS refused a step.
pub fn harden() -> Result<Hardening, SessionError> {
    let mut lim = getrlimit(Resource::Core);
    lim.current = Some(0);
    lim.maximum = Some(0);
    setrlimit(Resource::Core, lim)
        .map_err(|e| SessionError::Unprotected(format!("rlimit: {e}")))?;
    dumpable()?;
    Ok(Hardening {
        core_limit_zero: getrlimit(Resource::Core).current == Some(0),
        non_dumpable: true,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn dumpable() -> Result<(), SessionError> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| SessionError::Unprotected(format!("PR_SET_DUMPABLE: {e}")))
}

#[cfg(target_os = "macos")]
fn dumpable() -> Result<(), SessionError> {
    const PT_DENY_ATTACH: libc::c_int = 31;
    // SAFETY: PT_DENY_ATTACH takes no pointers; the others are null/zero.
    let r = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(SessionError::Unprotected("PT_DENY_ATTACH".into()))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn dumpable() -> Result<(), SessionError> {
    Ok(())
}
