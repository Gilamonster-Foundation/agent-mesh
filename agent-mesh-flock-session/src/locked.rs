//! A value pinned in RAM: `mlock`ed from the moment it is boxed.

use crate::{Policy, SessionError};
/// Boxed `T`, locked in memory. `T`'s own `Drop` scrubs it (the signing key
/// zeroizes). Pages stay locked after the drop: `munlock` does not nest, so
/// unlocking could release a page another `Locked` still shares.
pub struct Locked<T> {
    inner: Box<T>,
    locked: bool,
}

impl<T> Locked<T> {
    /// Box and lock `value`.
    ///
    /// # Errors
    /// `mlock` failed and the policy is [`Policy::Locked`].
    pub fn new(value: T, policy: Policy) -> Result<Self, SessionError> {
        let mut inner = Box::new(value);
        let ptr = (&mut *inner as *mut T).cast();
        // SAFETY: `ptr` and the size describe the live heap allocation of `inner`.
        let locked = unsafe { rustix::mm::mlock(ptr, std::mem::size_of::<T>()) };
        match (locked, policy) {
            (Ok(()), _) => Ok(Self {
                inner,
                locked: true,
            }),
            (Err(e), Policy::Locked) => Err(SessionError::Unprotected(format!(
                "mlock: {e} (raise RLIMIT_MEMLOCK, or pass --allow-unlocked)"
            ))),
            (Err(_), Policy::AllowUnlocked) => Ok(Self {
                inner,
                locked: false,
            }),
        }
    }

    /// Whether the pages are actually locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Borrow the value.
    #[must_use]
    pub fn get(&self) -> &T {
        &self.inner
    }
}
