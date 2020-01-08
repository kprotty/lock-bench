use super::futex;
use core::{
    mem::{size_of, transmute},
    sync::atomic::{Ordering, AtomicU8, AtomicU32, AtomicI32, AtomicUsize},
};

pub struct OsLock {
    state: AtomicU32,
}

impl OsLock {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    #[inline]
    fn is_locked(&self) -> &AtomicU8 {
        unsafe { &*(self as *const _ as *const AtomicU8) }
    }
}

const WAKE: u32 = 1 << 8;
const WAIT: u32 = 1 << 9;

pub type Mutex<T> = lock_api::Mutex<OsLock, T>;
pub type MutexGuard<'a, T> = lock_api::MutexGuard<'a, OsLock, T>;

unsafe impl lock_api::RawMutex for OsLock {
    const INIT: Self = Self::new();

    type GuardMarker = lock_api::GuardSend;

    fn try_lock(&self) -> bool {
        self.is_locked().swap(1, Ordering::Acquire) == 0
    }

    fn lock(&self) {
        match get_backend() {
            Backend::WaitOnAddress => unsafe {
                let futex_lock = &*(self as *const _ as *const futex::FutexLock<OsFutex>);
                futex_lock.lock()
            },
            Backend::KeyedEvent(handle) => unsafe {
                const SPIN: usize = 40;
                if !self.try_lock() {
                    let mut spin = SPIN;
                    let mut waiters = self.state.load(Ordering::Relaxed);
                    loop {
                        if waiters & 1 == 0 {
                            if self.try_lock() {
                                return;
                            } else {
                                spin_loop_hint();
                                waiters = self.state.load(Ordering::Relaxed);
                            }
                        } else if spin != 0 {
                            unsafe { Sleep(0) };
                            spin -= 1;
                            waiters = self.state.load(Ordering::Relaxed);
                        } else {
                            match self.state.compare_exchange_weak(
                                waiters,
                                (waiters + WAIT) | 1,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            ) {
                                Err(w) => waiters = w,
                                Ok(_) => {
                                    let key = &self.state as *const _ as usize;
                                    let wait_for_keyed_event: extern "system" fn(
                                        EventHandle: usize,
                                        Key: usize,
                                        Alertable: usize,
                                        pTimeout: usize,
                                    ) -> usize = transmute(NT_WAIT_FOR_KEYED_EVENT.load(Ordering::Relaxed));
                                    let r = (wait_for_keyed_event)(handle, key, 0, 0);
                                    debug_assert_eq!(r, 0);
                                    spin = SPIN;
                                    waiters = self.state.fetch_sub(WAKE, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            },
        }
    }

    fn unlock(&self) {
        match get_backend() {
            Backend::WaitOnAddress => unsafe {
                let futex_lock = &*(self as *const _ as *const futex::FutexLock<OsFutex>);
                futex_lock.unlock()
            },
            Backend::KeyedEvent(handle) => unsafe {
                self.is_locked().store(0, Ordering::Release);
                let mut waiters = self.state.load(Ordering::Relaxed);
                while !((waiters < WAIT) || (waiters & 1 != 0) || (waiters & WAKE != 0)) {
                    match self.state.compare_exchange_weak(
                        waiters,
                        waiters - WAIT + WAKE,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        Err(w) => waiters = w,
                        Ok(_) => {
                            let release_keyed_event: extern "system" fn(
                                EventHandle: usize,
                                Key: usize,
                                Alertable: usize,
                                pTimeout: usize,
                            ) -> usize = transmute(NT_RELEASE_KEYED_EVENT.load(Ordering::Relaxed));
                            let key = &self.state as *const _ as usize;
                            let r = (release_keyed_event)(handle, key, 0, 0);
                            debug_assert_eq!(r, 0);
                            return;
                        }
                    }
                }
            },
        }
    }
}

pub struct OsFutex;

unsafe impl futex::Futex for OsFutex {
    fn wake(ptr: *const i32) {
        unsafe {
            let wake_by_address_single: extern "system" fn(Address: usize) = 
                transmute(WAKE_BY_ADDRESS_SINGLE.load(Ordering::Relaxed));
            (wake_by_address_single)(ptr as usize);
        }
    }

    fn wait(ptr: *const i32, expected: i32) {
        unsafe {
            let atomic_ptr = &*(ptr as *const AtomicI32);
            let wait_on_address: extern "system" fn(
                Address: usize,
                CompareAddress: usize,
                AddrressSize: usize,
                dwMilliseconds: u32,
            ) -> i32 = transmute(WAIT_ON_ADDRESS.load(Ordering::Relaxed));
            while atomic_ptr.load(Ordering::Acquire) == expected {
                let r = (wait_on_address)(
                    ptr as usize,
                    &expected as *const _ as usize,
                    size_of::<i32>(),
                    !0u32,
                );
                debug_assert_eq!(r, 0);
            }
        }
    }
}

const WAIT_ON_ADDRESS_HANDLE: usize = !0;
static HANDLE: AtomicUsize = AtomicUsize::new(0);

enum Backend {
    WaitOnAddress,
    KeyedEvent(usize),
}

fn get_backend() -> Backend {
    match HANDLE.load(Ordering::Acquire) {
        0 => unsafe {
            if load_keyed_events() {
                Backend::KeyedEvent(HANDLE.load(Ordering::Acquire))
            } else if load_wait_on_address() {
                Backend::WaitOnAddress
            } else {
                unreachable!("WordLock requires WaitOnAddress (Win8+) or NT Keyed Events (WinXP+)");
            }
        },
        WAIT_ON_ADDRESS_HANDLE => Backend::WaitOnAddress,
        handle => Backend::KeyedEvent(handle),
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn Sleep(dwMilliseconds: u32);
    fn CloseHandle(handle: usize) -> i32;
    fn GetModuleHandleA(lpModuleName: *const u8) -> usize;
    fn GetProcAddress(lpModule: usize, lpFuncname: *const u8) -> usize;
}

static WAKE_BY_ADDRESS_SINGLE: AtomicUsize = AtomicUsize::new(0);
static WAIT_ON_ADDRESS: AtomicUsize = AtomicUsize::new(0);

unsafe fn load_wait_on_address() -> bool {
    let dll = GetModuleHandleA(b"api-ms-win-core-synch-l1-2-0.dll\0".as_ptr());
    if dll == 0 {
        return false;
    }

    let wait = GetProcAddress(dll, b"WaitOnAddress\0".as_ptr());
    if wait == 0 {
        return false;
    } else {
        WAIT_ON_ADDRESS.store(wait, Ordering::Relaxed);
    }

    let wake = GetProcAddress(dll, b"WakeByAddressSingle\0".as_ptr());
    if wake == 0 {
        return false;
    } else {
        WAKE_BY_ADDRESS_SINGLE.store(wake, Ordering::Relaxed);
    }

    HANDLE.store(WAIT_ON_ADDRESS_HANDLE, Ordering::Release);
    true
}

static NT_RELEASE_KEYED_EVENT: AtomicUsize = AtomicUsize::new(0);
static NT_WAIT_FOR_KEYED_EVENT: AtomicUsize = AtomicUsize::new(0);

unsafe fn load_keyed_events() -> bool {
    let dll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if dll == 0 {
        return false;
    }

    let create = GetProcAddress(dll, b"NtCreateKeyedEvent\0".as_ptr());
    if create == 0 {
        return false;
    }

    let wait = GetProcAddress(dll, b"NtWaitForKeyedEvent\0".as_ptr());
    if wait == 0 {
        return false;
    } else {
        NT_WAIT_FOR_KEYED_EVENT.store(wait, Ordering::Relaxed);
    }

    let wake = GetProcAddress(dll, b"NtReleaseKeyedEvent\0".as_ptr());
    if wake == 0 {
        return false;
    } else {
        NT_RELEASE_KEYED_EVENT.store(wake, Ordering::Relaxed);
    }

    let create = transmute::<usize, extern "system" fn(
        EventHandle: *mut usize,
        DesiredAccess: u32,
        ObjectAttributes: usize,
        Flags: u32,
    ) -> usize>(create);
    let mut handle = 0;
    if (create)(&mut handle, 0x80000000 | 0x40000000, 0, 0) != 0 {
        return false;
    }

    match HANDLE.compare_exchange(0, handle, Ordering::Release, Ordering::Relaxed) {
        Ok(_) => true,
        Err(_) => {
            let r = CloseHandle(handle);
            debug_assert_eq!(r, 0);
            true
        }
    }
}

