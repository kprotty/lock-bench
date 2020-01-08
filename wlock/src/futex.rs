use core::{
    marker::PhantomData,
    sync::atomic::{Ordering, AtomicI32},
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
}

/// "Optimized Mutex" from https://locklessinc.com/articles/mutex_cv_futex/ 
unsafe impl<F: Futex> lock_api::RawMutex for FutexLock<F> {
    const INIT: Self = Self::new();

    type GuardMarker = lock_api::GuardSend;

    fn try_lock(&self) -> bool {
        self.state
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn lock(&self) {
        if let Err(mut state) = self.state.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed) {
            if state == 1 {
                state = self.state.swap(2, Ordering::Acquire);
            }
            while state != 0 {
                F::wait(&self.state as *const _ as *const i32, 2);
                state = self.state.swap(2, Ordering::Acquire);
            }
        }
    }

    fn unlock(&self) {
        if self.state.load(Ordering::Relaxed) == 2 {
            self.state.store(0, Ordering::Release);
        } else if self.state.swap(0, Ordering::Release) == 1 {
            return;
        }
        if self.state.load(Ordering::Relaxed) != 0 {
            if self.state.compare_exchange_weak(1, 2, Ordering::Release, Ordering::Relaxed).is_ok() {
                return;
            }
        }
        F::wake(&self.state as *const _ as *const i32);
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub type Mutex<F, T> = lock_api::Mutex<FutexLock<F>, T>;

#[cfg_attr(windows, allow(dead_code))]
pub type MutexGuard<'a, T, F> = lock_api::MutexGuard<'a, FutexLock<F>, T>;
