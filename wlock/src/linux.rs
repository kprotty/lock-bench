use super::futex;
use core::sync::atomic::{Ordering, AtomicI32};
use libc::{syscall, SYS_futex, FUTEX_WAIT, FUTEX_WAKE, FUTEX_PRIVATE_FLAG};

pub struct OsFutex;

unsafe impl futex::Futex for OsFutex {
    fn wake(ptr: *const i32) {
        let r = unsafe { syscall(SYS_futex, ptr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1) };
        debug_assert!(r == 0 || r == 1);
    }

    fn wait(ptr: *const i32, expected: i32) {
        unsafe {
            let atomic_ptr = &*(ptr as *const AtomicI32);
            while atomic_ptr.load(Ordering::Acquire) == expected {
                let r = syscall(SYS_futex, ptr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, expected, 0);
                debug_assert!(r == 0 || r == -1);
                if r == -1 {
                    let errno = *libc::__errno_location();
                    debug_assert!(errno == libc::EAGAIN || errno == libc::EINTR);
                }
            }
        }
    }
}

pub type Mutex<T> = futex::Mutex<OsFutex, T>;
pub type MutexGuard<'a, T> = futex::MutexGuard<'a, T, OsFutex>;
