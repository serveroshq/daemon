use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            attempt: 0,
        }
    }
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);

        jitter(ceiling)
    }

    pub fn ceiling(&self) -> Duration {
        let factor = 2u32.saturating_pow(self.attempt.min(16));

        self.base.saturating_mul(factor).min(self.cap)
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

fn jitter(ceiling: Duration) -> Duration {
    use rand::Rng;

    let millis = ceiling.as_millis().max(1) as u64;
    let picked = rand::thread_rng().gen_range(millis / 2..=millis);

    Duration::from_millis(picked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_doubles_then_caps() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let mut ceilings = Vec::new();

        for _ in 0..8 {
            ceilings.push(backoff.ceiling().as_secs());
            backoff.next_delay();
        }

        assert_eq!(ceilings, vec![1, 2, 4, 8, 16, 32, 60, 60]);
    }

    #[test]
    fn delays_are_jittered_within_half_and_full_ceiling() {
        let mut backoff = Backoff::new(Duration::from_secs(8), Duration::from_secs(60));

        for _ in 0..50 {
            let delay = backoff.next_delay();
            let ceiling = backoff.ceiling();

            assert!(delay <= ceiling);
            assert!(
                delay.as_millis() * 2 >= (ceiling.as_millis() / 2),
                "delay {delay:?} far below ceiling {ceiling:?}"
            );
        }
    }

    #[test]
    fn reset_starts_over() {
        let mut backoff = Backoff::default();
        backoff.next_delay();
        backoff.next_delay();
        backoff.reset();

        assert_eq!(backoff.ceiling(), Duration::from_secs(1));
    }
}
