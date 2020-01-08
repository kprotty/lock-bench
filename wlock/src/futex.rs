use core::{
    marker::PhantomData,
    sync::atomic::{Ordering, AtomicU8, AtomicI32},
};

pub unsafe trait Futex {
    fn wake(ptr: *const i32);
    fn wait(ptr: *const i32, expected: i32);
}

pub struct FutexLock<F> {
    state: AtomicI32,
    futex: PhantomData<F>,
}

impl<F> FutexLock<F> {
    pub const fn new() -> Self {
        Self {
            state: AtomicI32::new(0),
            futex: PhantomData,
        }
    }

    #[inline]
    fn is_locked(&self) -> &AtomicU8 {
        unsafe { &*(self as *const _ as *const AtomicU8) }
    }

    #[inline]
    fn is_contended(&self) -> &AtomicU8 {
        unsafe { &*(self as *const _ as *const AtomicU8).add(1) }
    }
}

/// "Optimized Mutex" from https://locklessinc.com/articles/mutex_cv_futex/ 
unsafe impl<F: Futex> lock_api::RawMutex for FutexLock<F> {
    const INIT: Self = Self::new();

    type GuardMarker = lock_api::GuardSend;

    fn try_lock(&self) -> bool {
        self.is_locked().swap(1, Ordering::Acquire) == 0
    }

    fn lock(&self) {
        if !self.try_lock() {
            while self.state.swap(257, Ordering::Acquire) & 1 != 0 {
                F::wait(&self.state as *const _ as *const i32, 2);
            }
        }
    }

    fn unlock(&self) {
        if self.state.load(Ordering::Relaxed) == 1 {
            if self.state.compare_exchange_weak(1, 0, Ordering::Release, Ordering::Relaxed).is_ok() {
                return;
            }
        }

        self.is_locked().store(0, Ordering::Release);
        if self.is_locked().load(Ordering::Relaxed) != 0 {
            return;
        }

        self.is_contended().store(0, Ordering::Release);
        F::wake(&self.state as *const _ as *const i32);
    }
}

pub type Mutex<F, T> = lock_api::Mutex<FutexLock<F>, T>;
pub type MutexGuard<'a, T, F> = lock_api::MutexGuard<'a, FutexLock<F>, T>;
