// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 AgentSight Project
//
// Bounded re-scan schedule for processes whose SSL attach came up empty.
//
// # Why this exists
//
// `SslSniff::attach_process` decides what to hook by reading `/proc/<pid>/maps`
// *once*, at whatever moment a trigger happens to fire. For a dynamically
// linked interpreter that is a race: `python3.11` maps `libssl.so.3` only when
// the interpreter imports `ssl`, which is after `execve`. The two triggers that
// exist — a procmon `Exec` event and the startup `scanner.scan()` — both
// routinely win that race the wrong way, and because nothing ever re-reads
// maps, the process stays unhooked for its whole life. In a sidecar deployment
// the collector starts *before* the workload, so the `Exec` trigger is the one
// that fires: every pod loses the race.
//
// The window is small — `import ssl` completes within a few hundred milliseconds
// of `execve` — so the schedule below is front-loaded rather than spread out.
// Retrying at +30 s (the shape the stale-reattach TTL uses) is useless here:
// the processes that lose this race are often short-lived, and #3034 records a
// headless agent call living for seconds.
//
// # Bounded in three ways
//
// 1. **Per pid**: `BACKOFFS.len()` retries, then the pid goes `Exhausted` and
//    stops being re-scanned on the fast path.
// 2. **Per trigger**: while a retry is already scheduled, further external
//    triggers for the same pid are suppressed *without reading maps*. This is
//    what stops a process that legitimately has no hookable SSL library (the
//    collector itself, statically linked Go binaries) from turning every DNS
//    query it makes into a full maps scan plus a WARN line.
// 3. **In total**: `MAX_QUEUED` entries, evicting the oldest by first-scan time.
//
// # Known limitation
//
// A process that loads its SSL library later than the whole retry window
// (≈15 s) — a REPL where a human types `import ssl` minutes in — is only
// picked up by the `SLOW_RECHECK` path, i.e. at most once a minute and only if
// some trigger still fires for it. That is a deliberate trade: the alternative
// is an unbounded scan rate for every process on the host. `exhausted_total()`
// exists so the case can be measured before anyone decides to widen the window.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Retry schedule after a scan that found nothing to hook.
///
/// Front-loaded on purpose: see the module docs. The full window is ~14.7 s.
const BACKOFFS: [Duration; 5] = [
    Duration::from_millis(200),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(10),
];

/// How often an `Exhausted` pid may be re-scanned when a trigger still fires.
///
/// Not zero: a slow `import ssl` is rare but real, and giving up permanently
/// would turn a timing quirk into permanent blindness. Once a minute per pid is
/// cheap and bounded.
const SLOW_RECHECK: Duration = Duration::from_secs(60);

/// [`SLOW_RECHECK`] in seconds, for log messages.
pub(crate) const SLOW_RECHECK_SECS: u64 = SLOW_RECHECK.as_secs();

/// How many retries a pid gets before it goes `Exhausted`.
pub(crate) const RETRY_BUDGET: usize = BACKOFFS.len();

/// Wall-clock span of the whole retry schedule, in milliseconds. Derived from
/// `BACKOFFS` so a log message cannot drift away from the schedule it describes.
const fn backoff_total_ms() -> u64 {
    let mut total = 0u64;
    let mut i = 0;
    while i < BACKOFFS.len() {
        total += BACKOFFS[i].as_millis() as u64;
        i += 1;
    }
    total
}
pub(crate) const RETRY_WINDOW_MS: u64 = backoff_total_ms();

/// Hard cap on simultaneously scheduled pids.
///
/// A process storm (a build farm, a cron fleet) could otherwise grow the map
/// without bound; every entry is small but the count is not.
const MAX_QUEUED: usize = 1024;

/// What a single maps scan produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// At least one candidate attached successfully. Nothing to retry.
    Attached,
    /// Candidates existed but every one was legitimately unhookable (already
    /// negative-cached by inode in `traced_files`). Nothing to retry: the
    /// answer will not change without the file on disk changing, and a
    /// replaced file gets a new inode.
    UntraceableOnly,
    /// `maps` held no SSL candidate at all — the race this module exists for.
    NoCandidates,
    /// Candidates existed but every attach failed.
    AllFailed,
}

impl ScanOutcome {
    /// Whether this outcome means "stop retrying this pid".
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Attached | Self::UntraceableOnly)
    }
}

/// Whether an external trigger should actually scan `maps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanDecision {
    /// Scan now, then `report` the outcome.
    Proceed,
    /// Do not scan: a retry is already scheduled, or the pid is exhausted and
    /// its slow re-check is not due yet.
    Suppress,
}

/// A retry the driver should dispatch now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DueRetry {
    pub(crate) pid: u32,
    /// 1-based retry index.
    pub(crate) attempt: u8,
    /// Whether the retry budget is now spent, i.e. this is the last attempt.
    /// The caller turns a non-attached outcome on a final attempt into the one
    /// summary WARN for this pid.
    pub(crate) final_attempt: bool,
}

#[derive(Debug, Clone)]
enum Entry {
    Retrying {
        /// Retries dispatched so far; indexes into `BACKOFFS`.
        attempts: u8,
        next: Instant,
        /// Process name when the entry was created, for pid-recycle detection.
        /// `None` when it could not be read, which disables the check rather
        /// than failing every retry against an empty expectation.
        comm: Option<String>,
        first_scan: Instant,
    },
    Exhausted {
        last_scan: Instant,
        comm: Option<String>,
        first_scan: Instant,
    },
}

impl Entry {
    fn first_scan(&self) -> Instant {
        match self {
            Self::Retrying { first_scan, .. } | Self::Exhausted { first_scan, .. } => *first_scan,
        }
    }
}

/// Per-pid re-scan schedule. Pure bookkeeping: no I/O, no logging, and every
/// method takes `now` so the whole state machine is testable without sleeping.
#[derive(Debug, Default)]
pub(crate) struct AttachRetryQueue {
    entries: HashMap<u32, Entry>,
    exhausted_total: u64,
    suppressed_total: u64,
    evicted_total: u64,
}

impl AttachRetryQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// An external trigger (procmon `Exec`, DNS match, startup scan) arrived for
    /// `pid`, whose process name is `comm` (`None` if it could not be read).
    ///
    /// Returns whether the caller should scan `maps`, and — when it says
    /// `Proceed` for a pid not yet known — registers the first retry so the
    /// scan is followed up even if the caller's `report` is somehow lost.
    pub(crate) fn admit(&mut self, pid: u32, comm: Option<String>, now: Instant) -> ScanDecision {
        // Classify first, then mutate: holding the `entries` borrow across the
        // insert/remove below would not compile.
        enum Action {
            Fresh,
            Suppress,
            SlowRecheck,
            Recycled,
        }
        let action = match self.entries.get(&pid) {
            None => Action::Fresh,
            Some(Entry::Retrying { .. }) => {
                // A retry is already on the clock; scanning again now would only
                // repeat the same answer and, for a process that never has an SSL
                // library, repeat it once per DNS query.
                Action::Suppress
            }
            Some(Entry::Exhausted {
                last_scan,
                comm: stored,
                ..
            }) => {
                match (stored.as_deref(), comm.as_deref()) {
                    // A recycled pid must not inherit its predecessor's
                    // exhausted state, or the new process is never scanned.
                    (Some(a), Some(b)) if a != b => Action::Recycled,
                    _ if now.saturating_duration_since(*last_scan) >= SLOW_RECHECK => {
                        Action::SlowRecheck
                    }
                    _ => Action::Suppress,
                }
            }
        };

        match action {
            Action::Suppress => {
                self.suppressed_total += 1;
                ScanDecision::Suppress
            }
            Action::SlowRecheck => {
                self.bump_last_scan(pid, now);
                ScanDecision::Proceed
            }
            Action::Recycled => {
                self.entries.remove(&pid);
                self.insert_fresh(pid, comm, now);
                ScanDecision::Proceed
            }
            Action::Fresh => {
                self.insert_fresh(pid, comm, now);
                ScanDecision::Proceed
            }
        }
    }

    fn insert_fresh(&mut self, pid: u32, comm: Option<String>, now: Instant) {
        self.evict_if_full();
        // `Instant + Duration` only panics past the platform's monotonic range
        // (~584 billion years on Linux), so a sub-second backoff cannot
        // overflow it.
        let next = now + BACKOFFS[0];
        self.entries.insert(
            pid,
            Entry::Retrying {
                attempts: 0,
                next,
                comm,
                first_scan: now,
            },
        );
    }

    /// Report what a scan produced. Only terminal outcomes change state: the
    /// retry schedule was already advanced when the attempt was dispatched, so
    /// a failing scan needs no bookkeeping here.
    pub(crate) fn report(&mut self, pid: u32, outcome: ScanOutcome, now: Instant) {
        if outcome.is_terminal() {
            self.entries.remove(&pid);
            return;
        }
        // A slow re-check that still finds nothing must not resurrect the fast
        // schedule; it only pushes the next slow re-check out.
        if let Some(Entry::Exhausted { last_scan, .. }) = self.entries.get_mut(&pid) {
            *last_scan = now;
        }
    }

    /// Retries whose backoff has elapsed.
    ///
    /// `comm_of` re-reads the process name so a recycled pid is dropped instead
    /// of re-attached: `Probes::attach_process` registers the pid in the BPF
    /// `traced_processes` allowlist even when the SSL attach fails, so attaching
    /// to a reused pid would start collecting TLS plaintext from an unrelated
    /// process. procmon `Exit` normally clears the entry first (`forget`); this
    /// is the belt for that brace.
    pub(crate) fn take_due(
        &mut self,
        now: Instant,
        comm_of: impl Fn(u32) -> Option<String>,
    ) -> Vec<DueRetry> {
        let candidates: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(pid, e)| match e {
                Entry::Retrying { next, .. } if *next <= now => Some(*pid),
                _ => None,
            })
            .collect();

        let mut due = Vec::with_capacity(candidates.len());
        for pid in candidates {
            let Some(entry) = self.entries.remove(&pid) else {
                continue;
            };
            let (attempts, comm, first_scan) = match entry {
                Entry::Retrying {
                    attempts,
                    comm,
                    first_scan,
                    ..
                } => (attempts, comm, first_scan),
                Entry::Exhausted { .. } => continue,
            };

            match (&comm, comm_of(pid)) {
                // Process is gone; `forget` should already have cleared it, but
                // a missed procmon `Exit` must not leave a zombie entry behind.
                (_, None) => continue,
                // pid was recycled: a different process now answers to it.
                (Some(expected), Some(current)) if current != *expected => continue,
                // Same name, or nothing was recorded to compare against.
                _ => {}
            }

            let attempts = attempts.saturating_add(1);
            let final_attempt = attempts as usize >= BACKOFFS.len();
            if final_attempt {
                self.entries.insert(
                    pid,
                    Entry::Exhausted {
                        last_scan: now,
                        comm,
                        first_scan,
                    },
                );
                self.exhausted_total += 1;
            } else {
                let step = BACKOFFS
                    .get(attempts as usize)
                    .copied()
                    .unwrap_or(SLOW_RECHECK);
                let next = now + step;
                self.entries.insert(
                    pid,
                    Entry::Retrying {
                        attempts,
                        next,
                        comm,
                        first_scan,
                    },
                );
            }
            due.push(DueRetry {
                pid,
                attempt: attempts,
                final_attempt,
            });
        }
        due
    }

    /// Drop all state for `pid` (process exit).
    pub(crate) fn forget(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    /// Pids currently on the schedule.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many pids have spent their whole retry budget without ever
    /// attaching. This is the "silently collecting nothing" signal; until it is
    /// exported as a metric it is readable from the summary WARN.
    pub(crate) fn exhausted_total(&self) -> u64 {
        self.exhausted_total
    }

    /// How many external triggers were skipped because a retry was already
    /// scheduled. Diagnostics for the log-spam fix.
    pub(crate) fn suppressed_total(&self) -> u64 {
        self.suppressed_total
    }

    fn bump_last_scan(&mut self, pid: u32, now: Instant) {
        if let Some(Entry::Exhausted { last_scan, .. }) = self.entries.get_mut(&pid) {
            *last_scan = now;
        }
    }

    /// How many entries were dropped to stay under `MAX_QUEUED`. Non-zero means
    /// the host had more simultaneously-unhookable processes than the cap; the
    /// dropped pids simply never get their retry.
    pub(crate) fn evicted_total(&self) -> u64 {
        self.evicted_total
    }

    /// Evict the oldest entry when at capacity. Oldest = earliest first scan,
    /// which is the pid closest to (or already past) exhaustion and therefore
    /// the least valuable one to keep.
    fn evict_if_full(&mut self) {
        if self.entries.len() < MAX_QUEUED {
            return;
        }
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.first_scan())
            .map(|(pid, _)| *pid);
        if let Some(pid) = oldest {
            self.entries.remove(&pid);
            self.evicted_total += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PY: &str = "python3.11";

    fn comm(name: &str) -> Option<String> {
        Some(name.to_string())
    }

    /// A `comm_of` that always reports the process alive under `name`.
    fn alive(name: &'static str) -> impl Fn(u32) -> Option<String> {
        move |_| Some(name.to_string())
    }

    #[test]
    fn first_trigger_proceeds_and_arms_a_retry() {
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        assert_eq!(q.admit(42, comm(PY), t0), ScanDecision::Proceed);
        assert_eq!(q.len(), 1);
        // A failing scan must leave the retry armed — that is the whole point.
        q.report(42, ScanOutcome::NoCandidates, t0);
        assert_eq!(q.len(), 1);
        assert_eq!(
            q.take_due(t0 + BACKOFFS[0], alive(PY)),
            vec![DueRetry {
                pid: 42,
                attempt: 1,
                final_attempt: false
            }]
        );
    }

    #[test]
    fn trigger_while_a_retry_is_pending_is_suppressed() {
        // The log-spam fix: a process that never has a hookable SSL library is
        // triggered once per DNS query it makes, and must not be re-scanned
        // (or re-warned) each time.
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        assert_eq!(
            q.admit(35, comm("loongcollector"), t0),
            ScanDecision::Proceed
        );
        q.report(35, ScanOutcome::NoCandidates, t0);
        for i in 1..50 {
            assert_eq!(
                q.admit(
                    35,
                    comm("loongcollector"),
                    t0 + Duration::from_millis(i * 10)
                ),
                ScanDecision::Suppress,
                "trigger {i} should not re-scan while a retry is pending"
            );
        }
        assert_eq!(q.suppressed_total(), 49);
    }

    #[test]
    fn retry_is_not_due_before_its_backoff_elapses() {
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        q.admit(7, comm(PY), t0);
        q.report(7, ScanOutcome::NoCandidates, t0);
        assert!(
            q.take_due(t0 + BACKOFFS[0] - Duration::from_millis(1), alive(PY))
                .is_empty()
        );
        assert_eq!(q.take_due(t0 + BACKOFFS[0], alive(PY)).len(), 1);
    }

    #[test]
    fn schedule_is_front_loaded_and_spends_exactly_the_budget() {
        // Walks the whole schedule with a virtual clock: 5 retries over ~14.7 s,
        // then Exhausted. Guards both the front-loading (a 30 s-shaped schedule
        // would be useless for a process that lives for seconds) and the bound.
        let mut q = AttachRetryQueue::new();
        let mut now = Instant::now();
        q.admit(1, comm(PY), now);
        q.report(1, ScanOutcome::NoCandidates, now);

        let mut attempts = Vec::new();
        // 15 s of ticks at 50 ms, well past the ~14.7 s window.
        for _ in 0..300 {
            now += Duration::from_millis(50);
            for d in q.take_due(now, alive(PY)) {
                attempts.push(d.attempt);
                q.report(d.pid, ScanOutcome::AllFailed, now);
                assert_eq!(d.final_attempt, d.attempt as usize == BACKOFFS.len());
            }
        }

        assert_eq!(attempts, vec![1, 2, 3, 4, 5]);
        assert_eq!(q.exhausted_total(), 1);
        // Whole window is ~14.7 s, not minutes.
        assert!(BACKOFFS.iter().sum::<Duration>() < Duration::from_secs(20));
        assert!(
            BACKOFFS[0] <= Duration::from_millis(500),
            "first retry must fire inside the import-ssl window"
        );
        // Nothing left to dispatch.
        assert!(
            q.take_due(now + Duration::from_secs(600), alive(PY))
                .is_empty()
        );
    }

    #[test]
    fn terminal_outcomes_clear_the_entry() {
        for outcome in [ScanOutcome::Attached, ScanOutcome::UntraceableOnly] {
            let mut q = AttachRetryQueue::new();
            let t0 = Instant::now();
            q.admit(9, comm(PY), t0);
            q.report(9, outcome, t0);
            assert!(q.is_empty(), "{outcome:?} must cancel the schedule");
            assert_eq!(q.exhausted_total(), 0);
            // And a later trigger for the same pid is a fresh scan, not a
            // suppressed one — coverage may legitimately need re-establishing.
            assert_eq!(
                q.admit(9, comm(PY), t0 + Duration::from_secs(5)),
                ScanDecision::Proceed
            );
        }
    }

    #[test]
    fn exhausted_pid_is_suppressed_until_the_slow_recheck() {
        let mut q = AttachRetryQueue::new();
        let mut now = Instant::now();
        q.admit(3, comm(PY), now);
        // Burn the whole budget.
        for _ in 0..BACKOFFS.len() {
            now += BACKOFFS[0] + Duration::from_secs(11);
            let due = q.take_due(now, alive(PY));
            assert_eq!(due.len(), 1);
            q.report(3, ScanOutcome::AllFailed, now);
        }
        assert_eq!(q.exhausted_total(), 1);

        // Inside the slow-recheck interval: suppressed, so no maps read.
        assert_eq!(
            q.admit(3, comm(PY), now + SLOW_RECHECK - Duration::from_secs(1)),
            ScanDecision::Suppress
        );
        // Past it: one more look, so a late `import ssl` is not permanent blindness.
        let later = now + SLOW_RECHECK + Duration::from_secs(1);
        assert_eq!(q.admit(3, comm(PY), later), ScanDecision::Proceed);
        // And immediately suppressed again — at most one scan per interval.
        assert_eq!(
            q.admit(3, comm(PY), later + Duration::from_secs(1)),
            ScanDecision::Suppress
        );
        // A successful slow re-check clears the exhausted state entirely.
        q.report(3, ScanOutcome::Attached, later);
        assert!(q.is_empty());
    }

    #[test]
    fn recycled_pid_is_dropped_instead_of_attached() {
        // `Probes::attach_process` adds the pid to the BPF allowlist even when
        // the SSL attach fails, so dispatching a stale pid would start
        // collecting an unrelated process's TLS plaintext.
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        q.admit(100, comm(PY), t0);
        q.report(100, ScanOutcome::NoCandidates, t0);

        let due = q.take_due(t0 + BACKOFFS[0], alive("some-other-proc"));
        assert!(due.is_empty(), "a reused pid must not be dispatched");
        assert!(q.is_empty(), "and its entry must be dropped");
    }

    #[test]
    fn vanished_process_is_dropped() {
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        q.admit(101, comm(PY), t0);
        q.report(101, ScanOutcome::NoCandidates, t0);
        assert!(q.take_due(t0 + BACKOFFS[0], |_| None).is_empty());
        assert!(q.is_empty());
    }

    #[test]
    fn unreadable_comm_at_admit_still_dispatches() {
        // Failing to read `comm` must not silently disable retries: with no
        // expectation recorded there is nothing to compare against, so the
        // recycle check is skipped rather than failed.
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        assert_eq!(q.admit(102, None, t0), ScanDecision::Proceed);
        q.report(102, ScanOutcome::NoCandidates, t0);
        let due = q.take_due(t0 + BACKOFFS[0], alive(PY));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].pid, 102);
    }

    #[test]
    fn forget_on_exit_clears_the_schedule() {
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        q.admit(200, comm(PY), t0);
        q.forget(200);
        assert!(q.is_empty());
        assert!(
            q.take_due(t0 + Duration::from_secs(60), alive(PY))
                .is_empty()
        );
        // A recycled pid reusing 200 starts from scratch.
        assert_eq!(
            q.admit(200, comm("recycled"), t0 + Duration::from_secs(1)),
            ScanDecision::Proceed
        );
    }

    #[test]
    fn recycled_pid_does_not_inherit_the_exhausted_state() {
        // An exhausted entry is sticky by design; if the pid is later reused by
        // a different process, that process must still get scanned.
        let mut q = AttachRetryQueue::new();
        let mut now = Instant::now();
        q.admit(5, comm(PY), now);
        for _ in 0..BACKOFFS.len() {
            now += BACKOFFS[0] + Duration::from_secs(11);
            assert_eq!(q.take_due(now, alive(PY)).len(), 1);
            q.report(5, ScanOutcome::AllFailed, now);
        }
        assert_eq!(q.exhausted_total(), 1);

        // Same name: still suppressed inside the slow-recheck interval.
        let soon = now + Duration::from_secs(1);
        assert_eq!(q.admit(5, comm(PY), soon), ScanDecision::Suppress);
        // Different name: treated as a brand-new process, scanned immediately
        // and given a fresh retry budget.
        assert_eq!(q.admit(5, comm("node"), soon), ScanDecision::Proceed);
        q.report(5, ScanOutcome::NoCandidates, soon);
        assert_eq!(
            q.take_due(soon + BACKOFFS[0], alive("node")),
            vec![DueRetry {
                pid: 5,
                attempt: 1,
                final_attempt: false
            }]
        );
    }

    #[test]
    fn retry_window_constant_matches_the_schedule() {
        // Guards the number quoted in the summary WARN against drifting from
        // the schedule it describes.
        let summed: Duration = BACKOFFS.iter().copied().sum();
        assert_eq!(RETRY_WINDOW_MS, summed.as_millis() as u64);
        assert_eq!(RETRY_BUDGET, BACKOFFS.len());
        // Const block: `RETRY_WINDOW_MS` is a compile-time constant, so this is
        // a build-time invariant rather than a runtime observation.
        const {
            assert!(
                RETRY_WINDOW_MS < 20_000,
                "window should stay inside a short-lived process's life"
            )
        };
    }

    #[test]
    fn queue_is_bounded_and_counts_evictions() {
        let mut q = AttachRetryQueue::new();
        let t0 = Instant::now();
        let total = MAX_QUEUED + 10;
        for pid in 0..total as u32 {
            // Stagger first_scan so "oldest" is deterministic: pid 0 is oldest.
            q.admit(pid, comm(PY), t0 + Duration::from_millis(u64::from(pid)));
        }
        assert_eq!(q.len(), MAX_QUEUED);
        assert_eq!(q.evicted_total(), 10);
        // The oldest pids were the ones evicted.
        assert_eq!(
            q.admit(0, comm(PY), t0 + Duration::from_secs(1)),
            ScanDecision::Proceed
        );
        assert_eq!(
            q.admit(total as u32 - 1, comm(PY), t0 + Duration::from_secs(1)),
            ScanDecision::Suppress
        );
    }
}
