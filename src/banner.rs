//! `kunato banner`: the Kunato wordmark for a successful install or upgrade.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};

use crate::cli::BannerArgs;
use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rgb(u8, u8, u8);

const ORANGE: Rgb = Rgb(240, 138, 36);
const CREAM: Rgb = Rgb(255, 241, 224);
const TAGLINE_COLOR: Rgb = Rgb(176, 164, 154);
const VERSION_COLOR: Rgb = Rgb(240, 160, 72);

const LOGO_WIDTH: usize = 35;
const LOGO_BLOCK_HEIGHT: usize = WORDMARK.len() + 3;

const WORDMARK: [&str; 5] = [
    "█   █ █   █ █   █  ▀▀▀  ▀▀▀▀▀  ▀▀▀",
    "█  █  █   █ ██  █ █   █   █   █   █",
    "███   █   █ █ █ █ █████   █   █   █",
    "█  █  █   █ █  ██ █   █   █   █   █",
    "█   █  ▀▀▀  █   █ █   █   █    ▀▀▀",
];

const TAGLINE: &str = "P E R S O N A L   W A F";

pub fn run(args: BannerArgs) -> Result<(), Error> {
    let color = !args.no_color
        && io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").ok().is_none_or(|term| term != "dumb");
    let mut output = render(color, terminal_columns(), env!("CARGO_PKG_VERSION"));
    output.push('\n');
    let mut stdout = io::stdout().lock();
    if let Err(err) = stdout
        .write_all(output.as_bytes())
        .and_then(|_| stdout.flush())
        && err.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(Error::Message(format!("failed to write the banner: {err}")));
    }
    Ok(())
}

fn render(color: bool, width: usize, version: &str) -> String {
    let width = width.max(1);
    if width >= LOGO_WIDTH {
        render_logo(color, width, version)
    } else {
        render_compact(color, width, version)
    }
}

fn render_logo(color: bool, width: usize, version: &str) -> String {
    let margin = (width - LOGO_WIDTH) / 2;
    let mut output = String::new();
    for row in 0..LOGO_BLOCK_HEIGHT {
        push_margin(&mut output, margin);
        push_logo_row(&mut output, row, color, version);
        finish_line(&mut output, color);
    }
    output
}

fn render_compact(color: bool, width: usize, version: &str) -> String {
    let mut output = String::new();
    push_compact_line(&mut output, "KUNATO", width, color.then_some(ORANGE));
    if width >= "PERSONAL WAF".len() {
        push_compact_line(
            &mut output,
            "PERSONAL WAF",
            width,
            color.then_some(TAGLINE_COLOR),
        );
    }
    push_compact_line(
        &mut output,
        &format!("v{version}"),
        width,
        color.then_some(VERSION_COLOR),
    );
    output
}

fn push_compact_line(output: &mut String, text: &str, width: usize, color: Option<Rgb>) {
    if let Some(color) = color {
        push_foreground(output, color);
    }
    output.push_str(&centered(text, width));
    if color.is_some() {
        output.push_str("\x1b[0m");
    }
    output.push('\n');
}

fn push_margin(output: &mut String, margin: usize) {
    output.push_str(&" ".repeat(margin));
}

fn push_logo_row(output: &mut String, row: usize, color: bool, version: &str) {
    if row < WORDMARK.len() {
        let line = WORDMARK[row];
        let mut width = 0;
        for (column, glyph) in line.chars().enumerate() {
            if glyph == ' ' {
                output.push(' ');
            } else {
                if color {
                    push_foreground(output, logo_color(column, row));
                }
                output.push(glyph);
            }
            width += 1;
        }
        output.push_str(&" ".repeat(LOGO_WIDTH - width));
    } else if row == WORDMARK.len() {
        output.push_str(&" ".repeat(LOGO_WIDTH));
    } else if row == WORDMARK.len() + 1 {
        if color {
            push_foreground(output, TAGLINE_COLOR);
        }
        output.push_str(&centered(TAGLINE, LOGO_WIDTH));
    } else {
        if color {
            push_foreground(output, VERSION_COLOR);
        }
        output.push_str(&centered(&format!("v{version}"), LOGO_WIDTH));
    }
}

fn finish_line(output: &mut String, color: bool) {
    if color {
        output.push_str("\x1b[0m");
    } else {
        while output.ends_with(' ') {
            output.pop();
        }
    }
    output.push('\n');
}

fn centered(text: &str, width: usize) -> String {
    let length = text.chars().count();
    if length >= width {
        return text.to_owned();
    }
    let left = (width - length) / 2;
    let right = width - length - left;
    let mut line = String::with_capacity(width);
    line.push_str(&" ".repeat(left));
    line.push_str(text);
    line.push_str(&" ".repeat(right));
    line
}

fn logo_color(column: usize, row: usize) -> Rgb {
    let span = (LOGO_WIDTH - 1 + (WORDMARK.len() - 1) * 3) as f32;
    let position = (column + row * 3) as f32;
    lerp(ORANGE, CREAM, position / span)
}

fn lerp(from: Rgb, to: Rgb, amount: f32) -> Rgb {
    let amount = amount.clamp(0.0, 1.0);
    Rgb(
        (from.0 as f32 + (to.0 as f32 - from.0 as f32) * amount).round() as u8,
        (from.1 as f32 + (to.1 as f32 - from.1 as f32) * amount).round() as u8,
        (from.2 as f32 + (to.2 as f32 - from.2 as f32) * amount).round() as u8,
    )
}

fn push_foreground(output: &mut String, color: Rgb) {
    let _ = write!(output, "\x1b[38;2;{};{};{}m", color.0, color.1, color.2);
}

fn terminal_columns() -> usize {
    terminal_size()
        .or_else(|| {
            std::env::var("COLUMNS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        })
        .filter(|columns| (1..=4096).contains(columns))
        .unwrap_or(80)
}

#[cfg(unix)]
fn terminal_size() -> Option<usize> {
    // SAFETY: TIOCGWINSZ writes a winsize into the pointer and returns 0 on
    // success; the struct is zeroed and only read after that check.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::ioctl(
            libc::STDOUT_FILENO,
            libc::TIOCGWINSZ,
            &mut size as *mut libc::winsize,
        )
    };
    if result == 0 && size.ws_col > 0 {
        Some(usize::from(size.ws_col))
    } else {
        None
    }
}

#[cfg(not(unix))]
fn terminal_size() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(text: &str) -> String {
        let mut output = String::new();
        let mut characters = text.chars();
        while let Some(character) = characters.next() {
            if character == '\x1b' {
                if characters.next() == Some('[') {
                    for character in characters.by_ref() {
                        if ('@'..='~').contains(&character) {
                            break;
                        }
                    }
                }
            } else {
                output.push(character);
            }
        }
        output
    }

    #[test]
    fn wordmark_matches_the_layout() {
        assert!(
            WORDMARK
                .iter()
                .all(|line| line.chars().count() <= LOGO_WIDTH)
        );
        assert!(TAGLINE.chars().count() <= LOGO_WIDTH);
    }

    #[test]
    fn colored_output_uses_ansi_and_plain_output_does_not() {
        assert!(render(true, 80, "1.2.3").contains("\x1b[38;2;"));
        assert!(!render(false, 80, "1.2.3").contains('\x1b'));
    }

    #[test]
    fn logo_fits_eighty_columns() {
        let output = strip_ansi(&render(true, 80, "1.2.3"));
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), LOGO_BLOCK_HEIGHT);
        assert!(lines.iter().all(|line| line.chars().count() <= 80));
        assert!(output.contains("v1.2.3"));
        assert!(output.contains("P E R S O N A L"));
    }

    #[test]
    fn narrow_terminals_fall_back_to_compact() {
        let logo = strip_ansi(&render(false, 35, "1.2.3"));
        assert_eq!(logo.lines().count(), LOGO_BLOCK_HEIGHT);
        assert!(logo.lines().all(|line| line.chars().count() <= 35));

        let compact = strip_ansi(&render(false, 34, "1.2.3"));
        assert_eq!(compact.lines().count(), 3);
        assert!(compact.contains("KUNATO"));
        assert!(compact.contains("PERSONAL WAF"));
    }

    #[test]
    fn every_layout_fits_the_requested_width() {
        for width in [6, 12, 23, 34, 35, 40, 80, 120] {
            let output = strip_ansi(&render(true, width, "1.2.3"));
            for line in output.lines() {
                assert!(line.chars().count() <= width, "width {width}: {line:?}");
            }
        }
    }

    #[test]
    fn logo_gradient_runs_from_orange_to_cream() {
        assert_eq!(logo_color(0, 0), ORANGE);
        let end = logo_color(LOGO_WIDTH - 1, WORDMARK.len() - 1);
        assert!(end.0 >= 250);
        assert!(end.1 > 230);
        assert!(end.2 > 200);
    }
}
