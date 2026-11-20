//! Warmup, phase-specific input streams, sample summaries and rotated comparisons.

use std::time::{Duration, Instant};

use aw_mhac::common::{Res, Rng};

use super::Case;

pub type Repetition<'a> = Box<dyn FnMut(&mut Rng) -> Res<Vec<Duration>> + 'a>;
pub type Metric<'a> = (&'a str, &'a str);

pub struct Task<'a> {
    case: Case,
    metrics: &'a [Metric<'a>],
    run: Repetition<'a>,
    warm_rng: Rng,
    warm: Vec<Vec<f64>>,
    samples: Vec<Vec<f64>>,
    warmup_elapsed: Duration,
    warmup_stable: bool,
    timeout: Option<String>,
}

impl<'a> Task<'a> {
    pub fn new(case: Case, metrics: &'a [Metric<'a>], run: Repetition<'a>) -> Self {
        let warm_rng = case.operation_rng(metrics, "warmup");
        Self {
            case,
            metrics,
            run,
            warm_rng,
            warm: vec![Vec::new(); metrics.len()],
            samples: vec![Vec::new(); metrics.len()],
            warmup_elapsed: Duration::ZERO,
            warmup_stable: false,
            timeout: None,
        }
    }

    fn record(output: &mut [Vec<f64>], values: Vec<Duration>) -> Res<()> {
        if values.len() != output.len() {
            return Err("sampling row dimensions differ".into());
        }
        for (series, duration) in output.iter_mut().zip(values) {
            series.push(duration.as_secs_f64() * 1000.0);
        }
        Ok(())
    }

    fn warmup_once(&mut self) -> Res<()> {
        let start = Instant::now();
        let result = (self.run)(&mut self.warm_rng);
        self.warmup_elapsed += start.elapsed();
        match result {
            Ok(values) => Self::record(&mut self.warm, values),
            Err(error) if error.starts_with("trace timed out") => {
                self.timeout = Some(error);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn sample_once(&mut self, rng: &mut Rng) -> Res<()> {
        match (self.run)(rng) {
            Ok(values) => Self::record(&mut self.samples, values),
            Err(error) if error.starts_with("trace timed out") => {
                self.timeout = Some(error);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn warmed(&self, minimum: Duration, minimum_runs: usize) -> bool {
        self.timeout.is_some()
            || self.warm[0].len() >= minimum_runs && self.warmup_elapsed >= minimum
    }

    fn check_warm_tail(&mut self) {
        const WINDOW: usize = 5;
        self.warmup_stable = self.warm.iter().all(|series| {
            if series.len() < 2 * WINDOW {
                return false;
            }
            let tail = &series[series.len() - 2 * WINDOW..];
            let first = quantile(&tail[..WINDOW], 0.5);
            let last = quantile(&tail[WINDOW..], 0.5);
            first > 0.0 && (last - first).abs() <= first * 0.05
        });
    }

    fn repetitions(&self) -> usize {
        if self.timeout.is_some() {
            return 0;
        }
        if self.case.formal
            && self.case.runs == 100
            && self
                .warm
                .iter()
                .any(|series| quantile(series, 0.5) > 1000.0)
        {
            return 20;
        }
        self.case.runs
    }

    fn report(&self, goal: usize) {
        for ((name, role), series) in self.metrics.iter().zip(&self.samples) {
            let used = series.len().to_string();
            let warm_count = self.warm[0].len().to_string();
            let warm_seconds = format!("{:.9}", self.warmup_elapsed.as_secs_f64());
            let stable = self.warmup_stable.to_string();
            if let Some(error) = &self.timeout {
                let note =
                    format!("{error}; successful_warmups={warm_count}; successful_samples={used}");
                self.case.emit(
                    name,
                    role,
                    [
                        &used,
                        "",
                        "",
                        "",
                        "",
                        &note,
                        &warm_count,
                        &warm_seconds,
                        &stable,
                        "",
                    ],
                );
                continue;
            }
            let p25 = format!("{:.9}", quantile(series, 0.25));
            let median = format!("{:.9}", quantile(series, 0.5));
            let p75 = format!("{:.9}", quantile(series, 0.75));
            let blocks = series
                .chunks(100)
                .map(|block| format!("{:.9}", quantile(block, 0.5)))
                .collect::<Vec<_>>()
                .join(":");
            let note = if goal != self.case.runs {
                "slow warmup median exceeded 1 s"
            } else {
                ""
            };
            self.case.emit(
                name,
                role,
                [
                    &used,
                    &median,
                    &p25,
                    &p75,
                    "",
                    note,
                    &warm_count,
                    &warm_seconds,
                    &stable,
                    &blocks,
                ],
            );
        }
    }
}

fn quantile(series: &[f64], fraction: f64) -> f64 {
    let mut sorted = series.to_vec();
    sorted.sort_unstable_by(f64::total_cmp);
    let index = fraction * (sorted.len() - 1) as f64;
    let lo = sorted[index.floor() as usize];
    let hi = sorted[index.ceil() as usize];
    lo + (hi - lo) * index.fract()
}

pub fn rotate(mut tasks: Vec<Task<'_>>) -> Res<()> {
    let mut phase = 0;
    let number = tasks.len();
    let mut minimum_runs = tasks[0].case.warmup.max(10);
    let mut minimum = Duration::from_secs(1);
    // If the tail is unstable, execute additional active warmup windows and recheck.
    // A bounded retry preserves the evidence on noisy machines.
    for extension in 0..=8 {
        while tasks.iter().any(|task| !task.warmed(minimum, minimum_runs)) {
            for offset in 0..number {
                let task = &mut tasks[(phase + offset) % number];
                if task.timeout.is_none() {
                    task.warmup_once()?;
                }
            }
            phase = (phase + 1) % number;
        }
        for task in &mut tasks {
            if task.timeout.is_none() {
                task.check_warm_tail();
            }
        }
        if tasks
            .iter()
            .all(|task| task.timeout.is_some() || task.warmup_stable)
            || extension == 8
        {
            break;
        }
        minimum += Duration::from_millis(250);
        minimum_runs = tasks
            .iter()
            .filter(|task| task.timeout.is_none())
            .map(|task| task.warm[0].len())
            .min()
            .unwrap_or(minimum_runs)
            + 10;
    }

    let goals = tasks.iter().map(Task::repetitions).collect::<Vec<_>>();
    let mut rngs = tasks
        .iter()
        .map(|task| task.case.operation_rng(task.metrics, "samples"))
        .collect::<Vec<_>>();
    for round in 0..*goals.iter().max().unwrap_or(&0) {
        for offset in 0..number {
            let index = (round + offset) % number;
            let task = &mut tasks[index];
            if round < goals[index] && task.timeout.is_none() {
                task.sample_once(&mut rngs[index])?;
            }
        }
    }
    for (task, goal) in tasks.iter().zip(goals) {
        task.report(goal);
    }
    Ok(())
}
