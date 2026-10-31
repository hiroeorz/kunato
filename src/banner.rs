//! `kunato banner`: mascot and wordmark for a successful install or upgrade.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};

use crate::banner_art::{MASCOT_ASCII, MASCOT_HEIGHT, MASCOT_RGB, MASCOT_WIDTH};
use crate::cli::BannerArgs;
use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rgb(u8, u8, u8);

const CARD_BG: Rgb = Rgb(23, 19, 20);
const ORANGE: Rgb = Rgb(240, 138, 36);
const CREAM: Rgb = Rgb(255, 241, 224);
const TAGLINE_COLOR: Rgb = Rgb(176, 164, 154);
const VERSION_COLOR: Rgb = Rgb(240, 160, 72);

const LOGO_WIDTH: usize = 35;
const LOGO_GAP: usize = 3;
const CARD_PADDING_LEFT: usize = 1;
const CARD_PADDING_RIGHT: usize = 2;
const LOGO_BLOCK_HEIGHT: usize = WORDMARK.len() + 3;
const SIDE_BY_SIDE_WIDTH: usize =
    CARD_PADDING_LEFT + MASCOT_WIDTH + LOGO_GAP + LOGO_WIDTH + CARD_PADDING_RIGHT;
const SIDE_BY_SIDE_MIN: usize = SIDE_BY_SIDE_WIDTH + 1;

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
    if width >= SIDE_BY_SIDE_MIN {
        render_side_by_side(color, width, version)
    } else if width >= MASCOT_WIDTH {
        render_stacked(color, width, version)
    } else if width >= LOGO_WIDTH {
        render_logo_only(color, width, version)
    } else {
        render_compact(color, width, version)
    }
}

fn render_side_by_side(color: bool, width: usize, version: &str) -> String {
    let margin = (width - SIDE_BY_SIDE_WIDTH) / 2;
    let logo_top = (MASCOT_HEIGHT - LOGO_BLOCK_HEIGHT) / 2;
    let mut output = String::new();
    for row in 0..MASCOT_HEIGHT {
        push_margin(&mut output, margin);
        if color {
            push_background(&mut output, CARD_BG);
        }
        output.push_str(&" ".repeat(CARD_PADDING_LEFT));
        push_mascot_row(&mut output, row, color);
        if color {
            push_background(&mut output, CARD_BG);
        }
        output.push_str(&" ".repeat(LOGO_GAP));
        match row.checked_sub(logo_top) {
            Some(logo_row) if logo_row < LOGO_BLOCK_HEIGHT => {
                push_logo_row(&mut output, logo_row, color, version);
            }
            _ => output.push_str(&" ".repeat(LOGO_WIDTH)),
        }
        output.push_str(&" ".repeat(CARD_PADDING_RIGHT));
        finish_line(&mut output, color);
    }
    output
}

fn render_stacked(color: bool, width: usize, version: &str) -> String {
    let margin = (width - MASCOT_WIDTH) / 2;
    let mut output = String::new();
    for row in 0..LOGO_BLOCK_HEIGHT {
        push_margin(&mut output, margin);
        if color {
            push_background(&mut output, CARD_BG);
        }
        push_logo_row(&mut output, row, color, version);
        output.push(' ');
        finish_line(&mut output, color);
    }
    push_margin(&mut output, margin);
    if color {
        push_background(&mut output, CARD_BG);
        output.push_str(&" ".repeat(MASCOT_WIDTH));
        finish_line(&mut output, true);
    } else {
        finish_line(&mut output, false);
    }
    for row in 0..MASCOT_HEIGHT {
        push_margin(&mut output, margin);
        if color {
            push_background(&mut output, CARD_BG);
        }
        push_mascot_row(&mut output, row, color);
        finish_line(&mut output, color);
    }
    output
}

fn render_logo_only(color: bool, width: usize, version: &str) -> String {
    let margin = (width - LOGO_WIDTH) / 2;
    let mut output = String::new();
    for row in 0..LOGO_BLOCK_HEIGHT {
        push_margin(&mut output, margin);
        if color {
            push_background(&mut output, CARD_BG);
        }
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

fn push_mascot_row(output: &mut String, row: usize, color: bool) {
    if color {
        for column in 0..MASCOT_WIDTH {
            push_foreground(output, pixel(column, row * 2));
            push_background(output, pixel(column, row * 2 + 1));
            output.push('▀');
        }
    } else {
        let line = MASCOT_ASCII[row];
        let mut width = 0;
        for glyph in line.chars() {
            output.push(glyph);
            width += 1;
        }
        output.push_str(&" ".repeat(MASCOT_WIDTH - width));
    }
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
    let span = (LOGO_WIDTH + WORDMARK.len() * 3) as f32;
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

fn pixel(column: usize, row: usize) -> Rgb {
    let offset = (row * MASCOT_WIDTH + column) * 6;
    let bytes = MASCOT_RGB.as_bytes();
    Rgb(
        hex_pair(bytes[offset], bytes[offset + 1]),
        hex_pair(bytes[offset + 2], bytes[offset + 3]),
        hex_pair(bytes[offset + 4], bytes[offset + 5]),
    )
}

fn hex_pair(high: u8, low: u8) -> u8 {
    hex_digit(high) * 16 + hex_digit(low)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn push_foreground(output: &mut String, color: Rgb) {
    let _ = write!(output, "\x1b[38;2;{};{};{}m", color.0, color.1, color.2);
}

fn push_background(output: &mut String, color: Rgb) {
    let _ = write!(output, "\x1b[48;2;{};{};{}m", color.0, color.1, color.2);
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
    fn art_payload_matches_the_layout() {
        assert_eq!(MASCOT_RGB.len(), MASCOT_WIDTH * MASCOT_HEIGHT * 2 * 6);
        assert!(MASCOT_RGB.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(MASCOT_ASCII.len(), MASCOT_HEIGHT);
        assert!(
            MASCOT_ASCII
                .iter()
                .all(|line| line.chars().count() <= MASCOT_WIDTH)
        );
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
    fn side_by_side_fits_eighty_columns() {
        let output = strip_ansi(&render(true, 80, "1.2.3"));
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), MASCOT_HEIGHT);
        assert!(lines.iter().all(|line| line.chars().count() <= 80));
        assert!(output.contains("v1.2.3"));
        assert!(output.contains("P E R S O N A L"));
    }

    #[test]
    fn narrow_terminals_stack_or_compact() {
        let stacked = strip_ansi(&render(false, 60, "1.2.3"));
        assert_eq!(
            stacked.lines().count(),
            LOGO_BLOCK_HEIGHT + 1 + MASCOT_HEIGHT
        );
        assert!(stacked.lines().all(|line| line.chars().count() <= 60));

        let compact = strip_ansi(&render(false, 30, "1.2.3"));
        assert!(compact.lines().all(|line| line.chars().count() <= 30));
        assert!(compact.contains("KUNATO"));
    }

    #[test]
    fn every_layout_fits_the_requested_width() {
        for width in [30, 35, 36, 60, 76, 77, 78, 80, 120] {
            let output = strip_ansi(&render(true, width, "1.2.3"));
            for line in output.lines() {
                assert!(line.chars().count() <= width, "width {width}: {line:?}");
            }
        }
    }

    #[test]
    fn top_left_pixel_is_the_card_background() {
        assert_eq!(pixel(0, 0), CARD_BG);
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
