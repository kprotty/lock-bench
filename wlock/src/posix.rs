use core::{
    ptr::null,
    cell::Cell,
    mem::align_of,
    sync::atomic::{fence, Ordering, AtomicUsize},
};
use libc::{
    pthread_cond_t,
    pthread_cond_wait,
    pthread_cond_signal,
    pthread_cond_destroy,
    PTHREAD_COND_INITIALIZER,
    pthread_mutex_t,
    pthread_mutex_lock,
    pthread_mutex_unlock,
    pthread_mutex_destroy,
    PTHREAD_MUTEX_INITALIZER,
};

const MUTEX_LOCK: usize = 1 << 0;
const QUEUE_LOCK: usize = 1 << 1;
const QUEUE_MASK: usize = !(MUTEX_LOCK | QUEUE_LOCK);

/// WordLock from https://github.com/Amanieu/parking_lot/blob/master/core/src/word_lock.rs
pub struct WordLock {
    state: AtomicUsize,
}

pub type Mutex<T> = lock_api::Mutex<WordLock, T>;
pub type MutexGuard<'a, T> = lock_api::MutexGuard<'a, WordLock, T>;

unsafe impl lock_api::RawMutex for WordLock {
    const INIT = Self::new();

    type GuardMarker = lock_api::GuardSend;

    fn try_lock(&self) -> bool {
        self.state
            .compare_exchage_weak(0, MUTEX_LOCK, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    fn lock(&self) {
        if !self.try_lock() {
            self.lock_slow();
        }
    }

    fn unlock(&self) {
        let state = self.state.fetch_sub(MUTEX_LOCK, Ordering::Release);
        if (state & QUEUE_LOCK == 0) && (state & QUEUE_MASK != 0) {
            self.unlock_slow();
        }
    }
}

impl WordLock {
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0)
        }
    }

    #[cold]
    fn lock_slow(&self) {
        let mut state = self.state.load(Ordering::Relaxed);
        while state & MUTEX_LOCK == 0 {
            match self.state.compare_exchage_weak(
                state,
                state | MUTEX_LOCK,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(s) => state = s,
            }
        }
        
        assert!(align_of::<QueueNode>() > !QUEUE_MASK);
        let mut node = QueueNode::new();

        loop {
            if state & MUTEX_LOCK == 0 {
                match self.state.compare_exchage_weak(
                    state,
                    state | MUTEX_LOCK,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(s) => state = s,
                }
                continue;
            }
            
            let head = (state & QUEUE_MASK) as *const QueueNode;
            node.set_next(head);
            if let Err(s) = self.state.compare_exchage_weak(
                state,
                (&node as *const _ as usize) | (state & !QUEUE_MASK),
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                state = s;
                continue;
            }

            node.wait();
            node.reset();
        }
    }

    #[cold]
    fn unlock_slow(&self) {
        let mut state = self.state.load(Ordering::Relaxed);
        loop {
            if (state & QUEUE_LOCK != 0) || (state & QUEUE_MASK == 0) {
                return;
            }
            match self.state.compare_exchage_weak(
                state,
                state | QUEUE_LOCK,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(s) => state = s,
            }
        }

        'outer: loop {
            let head = unsafe { &*((state & QUEUE_MASK) as *const QueueNode) };
            let tail = head.find_tail();
            head.tail.set(tail);

            if state & MUTEX_LOCK != 0 {
                match self.state.compare_exchage_weak(
                    state,
                    state & !QUEUE_LOCK,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(s) => state = s,
                }
                fence(Ordering::Acquire);
                continue;
            }

            let new_tail = unsafe { &* tail.prev.get() };
            if new_tail.is_null() {
                loop {
                    match self.state.compare_exchage_weak(
                        state,
                        state & MUTEX_LOCK,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(s) => state = s,
                    }
                    if state & QUEUE_MASK != 0 {
                        fence(Ordering::Acquire);
                        continue 'outer;
                    }
                }
            } else {
                head.tail.set(new_tail);
                self.state.fetch_and(!QUEUE_LOCK, Ordering::Release);
            }

            tail.notify();
            return;
        }
    }
}

struct QueueNode {
    is_notified: Cell<bool>,
    cond: Cell<pthread_cond_t>,
    mutex: Cell<pthread_mutex_t>,
    prev: Cell<*const QueueNode>,
    next: Cell<*const QueueNode>,
    tail: Cell<*const QueueNode>,
}

impl Drop for QueueNode {
    fn drop(&mut self) {
        unsafe {
            let r = pthread_mutex_destroy(self.mutex.as_ptr());
            if cfg!(target_os = "dragonfly") {
                debug_assert!(r == 0 || r == libc::EAGAIN);
            } else {
                debug_assert_eq!(r, 0);
            }

            let r = pthread_cond_destroy(self.cond.as_ptr());
            if cfg!(target_os = "dragonfly") {
                debug_assert!(r == 0 || r == libc::EAGAIN);
            } else {
                debug_assert_eq!(r, 0);
            }
        }
    }
}

impl QueueNode {
    pub const fn new() -> Self {
        Self {
            is_notified: Cell::new(false),
            cond: Cell::new(PTHREAD_COND_INITIALIZER),
            mutex: Cell::new(PTHREAD_MUTEX_INITALIZER),
            prev: Cell::new(null()),
            next: Cell::new(null()),
            tail: Cell::new(null()),
        }
    }

    #[inline]
    fn set_next(&self, head: *const QueueNode) {
        if head.is_null() {
            self.tail.set(self);
            self.next.set(null());
        } else {
            self.tail.set(null());
            self.next.set(head);
        }
    }

    #[inline]
    fn find_tail(&self) -> &QueueNode {
        unsafe {
            let mut current = self;
            while current.tail.get().is_null() {
                let next = &* current.next.get();
                next.prev.set(current);
                current = next;
            }
            &* current.tail.get()
        }
    }

    fn reset(&mut self) {
        self.prev.set(null());
        self.is_notified.set(false);
    }

    fn wait(&self) {
        unsafe {
            let r = pthread_mutex_lock(self.mutex.as_ptr());
            debug_assert_eq!(r, 0);

            while !self.is_notified.get() {
                let r = pthread_cond_wait(self.cond.as_ptr(), self.mutex.as_ptr());
                debug_assert_eq!(r, 0);
            }

            let r = pthread_mutex_unlock(self.mutex.as_ptr());
            debug_assert_eq!(r, 0);
        }
    }

    fn notify(&self) {
        unsafe {
            let r = pthread_mutex_lock(self.mutex.as_ptr());
            debug_assert_eq!(r, 0);

            if !self.is_notified.get() {
                self.is_notified.set(true);
                let r = pthread_cond_signal(self.cond.as_ptr());
                debug_assert_eq!(r, 0);
            }

            let r = pthread_mutex_unlock(self.mutex.as_ptr());
            debug_assert_eq!(r, 0);
        }
    }
}
