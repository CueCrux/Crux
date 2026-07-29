// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

use std::time::Duration;

use crate::ConnectionError;

/// Finite exponential retry schedule with a per-delay cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    initial: Duration,
    maximum: Duration,
    maximum_attempts: u32,
    attempts: u32,
}

impl Backoff {
    pub fn new(initial: Duration, maximum: Duration, maximum_attempts: u32) -> Result<Self, ConnectionError> {
        if initial.is_zero() || maximum.is_zero() || initial > maximum || maximum_attempts == 0 {
            return Err(ConnectionError::new("backoff bounds are invalid"));
        }
        Ok(Self {
            initial,
            maximum,
            maximum_attempts,
            attempts: 0,
        })
    }

    /// Return the next delay, or `None` once the finite budget is exhausted.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= self.maximum_attempts {
            return None;
        }
        let shift = self.attempts.min(31);
        let factor = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let delay = self
            .initial
            .checked_mul(factor)
            .unwrap_or(self.maximum)
            .min(self.maximum);
        self.attempts += 1;
        Some(delay)
    }

    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    pub const fn maximum_attempts(&self) -> u32 {
        self.maximum_attempts
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(250),
            maximum: Duration::from_secs(4),
            maximum_attempts: 5,
            attempts: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Backoff;

    #[test]
    fn schedule_is_finite_and_capped_and_resets() {
        let mut backoff = Backoff::new(Duration::from_millis(250), Duration::from_secs(1), 6).unwrap();
        let delays: Vec<_> = std::iter::from_fn(|| backoff.next_delay()).collect();
        assert_eq!(
            delays,
            vec![
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ]
        );
        assert_eq!(backoff.next_delay(), None);
        backoff.reset();
        assert_eq!(backoff.next_delay(), Some(Duration::from_millis(250)));
    }

    #[test]
    fn invalid_bounds_fail_closed() {
        assert!(Backoff::new(Duration::ZERO, Duration::from_secs(1), 1).is_err());
        assert!(Backoff::new(Duration::from_secs(2), Duration::from_secs(1), 1).is_err());
        assert!(Backoff::new(Duration::from_secs(1), Duration::from_secs(1), 0).is_err());
    }
}
