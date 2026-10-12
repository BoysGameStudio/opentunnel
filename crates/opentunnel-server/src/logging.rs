//! Log output: JSON lines (`LOG_FORMAT=json`, on Fly) or human-readable text. Each JSON line has `timestamp`,
//! `level`, `target`, `message`, the event's fields at the top level (by convention `tunnel`, `conn`, `route`,
//! `error`, `error_class`, `attempt`, ...), and the machine's `machine` and `region`. Nothing secret is ever
//! logged: tokens, keys and the database URL are never passed to a log macro.

use std::fmt;

use clap::ValueEnum;
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Json,
    Text,
}

/// Installs the global subscriber, filtered by `RUST_LOG`.
pub fn init(format: LogFormat, machine: Option<&str>, region: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,rustls=warn".into());
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter);
    match format {
        LogFormat::Text => builder
            .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
            .init(),
        LogFormat::Json => builder
            .with_ansi(false)
            .event_format(Json::new(machine, region))
            .init(),
    }
}

/// One JSON object per event.
pub struct Json {
    machine: Option<String>,
    region: String,
}

impl Json {
    pub fn new(machine: Option<&str>, region: &str) -> Self {
        Self {
            machine: machine.filter(|id| !id.is_empty()).map(str::to_owned),
            region: region.to_owned(),
        }
    }

    /// The line for an event with `fields`, without the trailing newline: the fixed keys first, then the
    /// event's fields, then where it ran.
    pub fn line(&self, level: &str, target: &str, mut fields: Map<String, Value>) -> String {
        let message = fields.remove("message").unwrap_or(Value::from(""));
        let mut entries: Vec<(&str, Value)> = vec![
            (
                "timestamp",
                crate::clock::iso(crate::clock::Clock::system().now_ms()).into(),
            ),
            ("level", level.into()),
            ("message", message),
            ("target", target.into()),
        ];
        let machine = self.machine.clone().map(Value::from);
        let region = Value::from(self.region.clone());
        let has = |key: &str| fields.contains_key(key);
        let (machine, region) = (
            machine.filter(|_| !has("machine")),
            (!has("region")).then_some(region),
        );
        entries.extend(
            fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.clone())),
        );
        entries.extend(machine.map(|value| ("machine", value)));
        entries.extend(region.map(|value| ("region", value)));
        let mut line = String::from("{");
        for (index, (key, value)) in entries.iter().enumerate() {
            if index > 0 {
                line.push(',');
            }
            line.push_str(&Value::from(*key).to_string());
            line.push(':');
            line.push_str(&value.to_string());
        }
        line.push('}');
        line
    }
}

impl<S, N> FormatEvent<S, N> for Json
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields(Map::new());
        event.record(&mut fields);
        let metadata = event.metadata();
        let level = metadata.level().as_str().to_ascii_lowercase();
        writeln!(writer, "{}", self.line(&level, metadata.target(), fields.0))
    }
}

struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0.insert(field.name().into(), value.to_string().into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_flat_json_lines() {
        let json = Json::new(Some("m1"), "iad");
        let mut fields = Map::new();
        fields.insert("message".into(), "attempt failed".into());
        fields.insert("attempt".into(), 2.into());
        fields.insert("error_class".into(), "nonce".into());
        let line: Value =
            serde_json::from_str(&json.line("warn", "opentunnel_server::jobs", fields)).unwrap();
        assert_eq!(line["level"], "warn");
        assert_eq!(line["message"], "attempt failed");
        assert_eq!(line["attempt"], 2);
        assert_eq!(line["error_class"], "nonce");
        assert_eq!(line["machine"], "m1");
        assert_eq!(line["region"], "iad");
        assert!(line["timestamp"].as_str().unwrap().ends_with('Z'));
    }
}
