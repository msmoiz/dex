use colored::{Color, Colorize};
use env_logger::fmt::Formatter;
use std::io::Write;

/// Initialize the logger.
pub fn init_logger() {
    let format = |buf: &mut Formatter, record: &log::Record| {
        use log::Level::*;
        let level = {
            let color = match record.level() {
                Error => Color::Red,
                Warn => Color::Yellow,
                Info => Color::Blue,
                Debug => Color::Green,
                Trace => Color::Magenta,
            };

            let text = match record.level() {
                Warn => String::from("warning"),
                _ => record.level().to_string(),
            };

            text.to_string().to_lowercase().color(color).bold()
        };

        writeln!(buf, "{level}{} {}", ":".bold(), record.args())
    };

    env_logger::builder()
        .format(format)
        .filter_level(log::LevelFilter::Warn)
        .init();
}
