//! Immutable snapshots shared by the request path and reload tasks.
//!
//! Readers clone the inner `Arc`, so they never hold a lock guard across an
//! `await`. Writers replace the whole snapshot under a short write lock.

use std::sync::{Arc, PoisonError, RwLock};

pub struct Snapshot<T> {
    current: RwLock<Arc<T>>,
}

impl<T> Snapshot<T> {
    pub fn new(value: T) -> Self {
        Self::from_arc(Arc::new(value))
    }

    pub fn from_arc(value: Arc<T>) -> Self {
        Self {
            current: RwLock::new(value),
        }
    }

    pub fn load(&self) -> Arc<T> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn store(&self, value: Arc<T>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

pub(crate) struct SnapshotOption<T> {
    current: RwLock<Option<Arc<T>>>,
}

impl<T> SnapshotOption<T> {
    pub(crate) fn empty() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    pub(crate) fn load(&self) -> Option<Arc<T>> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn store(&self, value: Option<Arc<T>>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

#[cfg(test)]
mod tests {
    use super::{Snapshot, SnapshotOption};
    use std::sync::Arc;

    #[test]
    fn loads_and_replaces_the_snapshot() {
        let snapshot = Snapshot::new(1_u32);
        assert_eq!(*snapshot.load(), 1);
        snapshot.store(Arc::new(2));
        assert_eq!(*snapshot.load(), 2);
    }

    #[test]
    fn option_snapshot_starts_empty_and_can_be_cleared() {
        let snapshot = SnapshotOption::empty();
        assert!(snapshot.load().is_none());
        snapshot.store(Some(Arc::new(7_u32)));
        assert_eq!(*snapshot.load().expect("value"), 7);
        snapshot.store(None);
        assert!(snapshot.load().is_none());
    }

    #[test]
    fn a_poisoned_snapshot_still_loads_and_stores() {
        let snapshot = Arc::new(Snapshot::new(1_u32));
        let writer = Arc::clone(&snapshot);
        let result = std::thread::spawn(move || {
            let _guard = writer.current.write().expect("write");
            panic!("poison the snapshot");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(*snapshot.load(), 1);
        snapshot.store(Arc::new(2));
        assert_eq!(*snapshot.load(), 2);
    }
}
