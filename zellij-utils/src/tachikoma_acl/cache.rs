//! Minimal in-memory TTL + LRU cache for ACL verify responses.
//!
//! We don't pull in the `lru` crate to keep the dep surface small. The
//! implementation is a `HashMap` of entries keyed by a stable 64-bit hash of
//! the request tuple, plus a `VecDeque` recording the most-recently-touched
//! keys for eviction. Cache capacity is fixed at 1024 entries and TTL at
//! 3 seconds, matching the values discussed in PLAN.md §8.
//!
//! Thread-safety is provided by wrapping the inner state in a `Mutex`. A
//! `Mutex` is acceptable here because:
//!   - lookups are cheap (a single hashmap probe + a `VecDeque::retain`),
//!   - contention is low (at most a few requests per second per session).
//!
//! Eviction policy
//! ---------------
//! 1. On `get()`, expired entries are evicted lazily.
//! 2. On `insert()`, if at capacity, the oldest-accessed key is dropped.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::types::VerifyResponse;

/// Cache TTL — short on purpose: ACL revocation must propagate quickly.
pub const TTL: Duration = Duration::from_secs(3);

/// Maximum number of cached entries before LRU eviction kicks in.
pub const CAPACITY: usize = 1024;

#[derive(Clone)]
struct Entry {
    response: VerifyResponse,
    inserted_at: Instant,
}

/// A small, thread-safe TTL+LRU store keyed on a 64-bit hash of the request.
pub struct TtlLru {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

struct Inner {
    map: HashMap<u64, Entry>,
    /// Front = oldest, back = newest (most recently accessed).
    order: VecDeque<u64>,
}

impl TtlLru {
    pub fn new() -> Self {
        Self::with_params(CAPACITY, TTL)
    }

    pub fn with_params(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(capacity),
                order: VecDeque::with_capacity(capacity),
            }),
            ttl,
            capacity,
        }
    }

    /// Stable key derived from the request tuple.
    pub fn key(
        token: &str,
        context_path: Option<&str>,
        session_name: Option<&str>,
        action: &str,
    ) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        token.hash(&mut h);
        context_path.hash(&mut h);
        session_name.hash(&mut h);
        action.hash(&mut h);
        h.finish()
    }

    pub fn get(&self, key: u64) -> Option<VerifyResponse> {
        let mut inner = self.inner.lock().ok()?;
        let entry = inner.map.get(&key)?.clone();
        if entry.inserted_at.elapsed() > self.ttl {
            // Expired — evict and miss.
            inner.map.remove(&key);
            inner.order.retain(|k| *k != key);
            return None;
        }
        // Promote to most-recently-used.
        inner.order.retain(|k| *k != key);
        inner.order.push_back(key);
        Some(entry.response)
    }

    pub fn insert(&self, key: u64, response: VerifyResponse) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.map.len() >= self.capacity && !inner.map.contains_key(&key) {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
        inner.order.retain(|k| *k != key);
        inner.order.push_back(key);
        inner.map.insert(
            key,
            Entry {
                response,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Forcibly drop every entry. Useful when an admin revokes a token and
    /// we want to invalidate the local cache aggressively.
    #[allow(dead_code)]
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.map.clear();
            inner.order.clear();
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|i| i.map.len()).unwrap_or(0)
    }
}

impl Default for TtlLru {
    fn default() -> Self {
        Self::new()
    }
}
