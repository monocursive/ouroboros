//! A10: the palette as a value, from the config file through `/theme` to the drawn frame.
//!
//! The pure half of theme resolution — the matrix, the contrast check, the token walk, the
//! OSC 11 parse — lives beside the code in `src/ui/theme.rs`, because none of it needs a
//! frame. What is here is the half that only a rendered screen can show: that switching
//! the palette actually changes the bytes, that the config file is written with the name
//! that was chosen, and that a name this build does not have is refused by name.
//!
//! ## Why these tests serialise
//!
//! The active palette is process-wide, and `cargo test` runs a binary's tests on many
//! threads. A test that installed `light` while another asserted `cyan` would fail on
//! neither's account. [`THEME`] is the mutex that makes each of these the only one
//! touching the palette, and every one of them puts it back.

mod support;

use std::sync::{Mutex, MutexGuard};

use crossterm::event::KeyCode;
use ouro::config::{Config, ThemeConfig};
use ouro::ui::app::{App, Msg, Overlay};
use ouro::ui::theme::{self, Palette, ThemeName};

use support::{app, full_hello, render, Screen};

static THEME: Mutex<()> = Mutex::new(());

/// Holds the palette still for one test, and restores it however the test ends.
struct Held<'a> {
    _guard: MutexGuard<'a, ()>,
    restore: Palette,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        theme::install(self.restore);
    }
}

fn hold() -> Held<'static> {
    let guard = THEME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    Held {
        _guard: guard,
        restore: theme::current().palette,
    }
}

fn opened(config: Config) -> App {
    let mut app = app(full_hello());
    app.config = config;
    app.config_path = Some(std::path::PathBuf::from(
        "/home/operator/.config/ouroboros/config.toml",
    ));
    app
}

fn typed(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(Msg::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(character),
            crossterm::event::KeyModifiers::NONE,
        )));
    }

    app.apply(Msg::Key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    )));
}

fn frame(app: &mut App) -> Screen {
    render(app, 100, 30)
}

fn press(app: &mut App, code: crossterm::event::KeyCode) {
    app.apply(Msg::Key(crossterm::event::KeyEvent::new(
        code,
        crossterm::event::KeyModifiers::NONE,
    )));
}

#[test]
fn the_dark_palette_is_what_draws_when_nothing_asked_for_anything_else() {
    let _held = hold();
    theme::install(theme::resolve(ThemeName::Auto, false, None));

    let mut app = opened(Config::default());
    let screen = frame(&mut app);

    // The header's own channel, unchanged from before themes existed.
    assert_eq!(theme::system(), ratatui::style::Color::Cyan);
    assert!(!screen.text().is_empty());
}

#[test]
fn a_named_theme_in_the_config_file_is_the_one_that_draws() {
    let _held = hold();

    for (name, palette, system) in [
        (
            "light",
            Palette::Light,
            ratatui::style::Color::Rgb(0, 92, 175),
        ),
        ("ansi", Palette::Ansi, ratatui::style::Color::Blue),
        (
            "dark-daltonized",
            Palette::DarkDaltonized,
            ratatui::style::Color::Rgb(125, 211, 252),
        ),
    ] {
        let requested = ThemeName::parse(name).expect("a name this build has");
        theme::install(theme::resolve(requested, false, None));

        assert_eq!(theme::current().palette, palette, "{name}");
        assert_eq!(theme::system(), system, "{name}");
    }
}

#[test]
fn the_config_table_reads_its_own_name_and_falls_back_to_auto() {
    assert_eq!(ThemeConfig::default().name(), ThemeName::Auto);
    assert_eq!(
        ThemeConfig {
            name: Some("light-daltonized".into()),
        }
        .name(),
        ThemeName::LightDaltonized
    );
    // A name normalisation already dropped, or one from a newer build: `auto`, not a
    // panic and not a guess.
    assert_eq!(
        ThemeConfig {
            name: Some("solarized".into()),
        }
        .name(),
        ThemeName::Auto
    );
}

/// T2.9. Bare `/theme` opens the list instead of cycling *and writing* in one keystroke.
///
/// The review changed the reviewer's theme by reading the code that does it: the verb
/// cycled one palette forward and saved `config.toml` on the spot, so "look at the next
/// one" and "keep the next one" were the same press with no way back that did not write
/// again. Delete the `previous` restore in `overlay_key` and this goes red.
#[test]
fn bare_slash_theme_opens_a_picker_that_previews_before_it_writes() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());
    app.config.theme.name = Some("dark".into());
    theme::install(theme::resolve(ThemeName::Dark, false, None));
    ouro::ui::switch_theme(ThemeName::Dark);
    let _ = app.take_config_save();

    typed(&mut app, "/theme");
    assert!(
        matches!(app.overlay, Some(Overlay::Theme { .. })),
        "bare /theme did not open the picker"
    );

    let screen = frame(&mut app);
    assert!(screen.contains("light-daltonized"), "{}", screen.text());
    assert!(
        screen.contains("esc puts back"),
        "the picker never says what esc does: {}",
        screen.text()
    );

    // Moving is a preview: the palette changes, the config does not, and nothing is
    // queued for the driver to write.
    press(&mut app, KeyCode::Down);
    assert_eq!(theme::current().palette, Palette::Light, "moving previews");
    assert_eq!(app.config.theme.name.as_deref(), Some("dark"));
    assert!(
        app.take_config_save().is_none(),
        "a preview asked for a write"
    );

    // Esc puts back exactly what was drawing, and still writes nothing.
    press(&mut app, KeyCode::Esc);
    assert!(app.overlay.is_none());
    assert_eq!(
        theme::current().palette,
        Palette::Dark,
        "esc did not restore"
    );
    assert_eq!(app.config.theme.name.as_deref(), Some("dark"));
    assert!(app.take_config_save().is_none(), "esc wrote config.toml");
}

/// The other half of the same overlay: `Enter` is the press that keeps it.
#[test]
fn enter_in_the_theme_picker_saves_the_previewed_palette() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());
    ouro::ui::switch_theme(ThemeName::Dark);
    app.config.theme.name = Some("dark".into());
    let _ = app.take_config_save();

    typed(&mut app, "/theme");
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);

    assert!(app.overlay.is_none());
    assert_eq!(theme::current().palette, Palette::Ansi);
    assert_eq!(app.config.theme.name.as_deref(), Some("ansi"));
    assert!(
        app.take_config_save().is_some(),
        "enter did not ask for a write"
    );
}

#[test]
fn slash_theme_with_a_name_goes_straight_to_it() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());

    typed(&mut app, "/theme light-daltonized");
    assert_eq!(theme::current().palette, Palette::LightDaltonized);
    assert_eq!(app.config.theme.name.as_deref(), Some("light-daltonized"));
}

#[test]
fn a_theme_this_build_does_not_have_is_named_rather_than_swapped() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());
    typed(&mut app, "/theme solarized");

    let screen = frame(&mut app);
    let text = screen.text();

    assert!(text.contains("solarized"), "{text}");
    assert!(
        text.contains("dark"),
        "the alternatives were not named: {text}"
    );
    // Nothing changed, and nothing was written down.
    assert_eq!(theme::current().palette, Palette::Dark);
    assert_eq!(app.config.theme.name, None);
}

#[test]
fn switching_the_palette_changes_the_bytes_on_screen() {
    let _held = hold();

    theme::install(Palette::Dark);
    let mut app = opened(Config::default());
    let dark = frame(&mut app);

    theme::install(Palette::Light);
    let light = frame(&mut app);

    // The words are the same; the colours are not. A theme that changed neither would pass
    // every other test in this file.
    assert_eq!(dark.rows, light.rows, "the palette changed the text");
    assert_ne!(
        dark.colours().collect::<Vec<_>>(),
        light.colours().collect::<Vec<_>>(),
        "the palette switch did not reach the frame"
    );
    // …and the colours that appeared are that palette's own, not an arbitrary difference.
    assert!(
        dark.colours()
            .any(|colour| colour == theme::PALETTES[0].system),
        "the dark frame drew nothing in the dark system colour"
    );
    assert!(
        light
            .colours()
            .any(|colour| colour == ratatui::style::Color::Rgb(0, 92, 175)),
        "the light frame drew nothing in the light system colour"
    );
    assert!(
        !light
            .colours()
            .any(|colour| colour == ratatui::style::Color::Cyan),
        "a dark-palette colour survived the switch"
    );
}

#[test]
fn no_color_leaves_every_word_in_the_terminals_own_colour() {
    let _held = hold();
    theme::install(theme::resolve(ThemeName::Light, true, None));

    assert_eq!(theme::current().palette, Palette::Monochrome);

    let mut app = opened(Config::default());
    let screen = frame(&mut app);

    let painted: Vec<_> = screen
        .colours()
        .filter(|colour| *colour != ratatui::style::Color::Reset)
        .collect();

    assert!(
        painted.is_empty(),
        "{} cell(s) were painted under NO_COLOR, starting with {:?}\n{}",
        painted.len(),
        painted.first(),
        screen.text()
    );
}

/// Review: the verb is a toggle, so pressing it twice is how someone checks what this
/// build has and gets back to what they were doing — and getting back must undo the
/// preview, exactly as `Esc` does. A second `/theme` that left the previewed palette
/// installed would be the write-on-look the picker exists to stop, one step removed.
#[test]
fn a_second_theme_verb_puts_the_previewed_palette_back() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());
    app.config.theme.name = Some("dark".into());
    ouro::ui::switch_theme(ThemeName::Dark);
    let _ = app.take_config_save();

    typed(&mut app, "/theme");
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_ne!(
        theme::current().palette,
        Palette::Dark,
        "moving did not preview"
    );

    // The verb's own entry point: the picker is a modal, so typing `/theme` again would
    // never reach the composer.
    app.open_theme_picker();

    assert!(
        app.overlay.is_none(),
        "the second verb left an overlay open"
    );
    assert_eq!(
        theme::current().palette,
        Palette::Dark,
        "the second verb kept the preview instead of putting back what was drawing"
    );
    assert!(
        app.take_config_save().is_none(),
        "reopening wrote config.toml"
    );
}

/// The picker opens on the theme that is configured, and lists every name this build has.
#[test]
fn the_picker_opens_on_the_configured_theme_and_lists_them_all() {
    let _held = hold();
    theme::install(Palette::Dark);

    let mut app = opened(Config::default());
    app.config.theme.name = Some("ansi".into());
    ouro::ui::switch_theme(ThemeName::Ansi);
    let _ = app.take_config_save();

    typed(&mut app, "/theme");

    match app.overlay.as_ref() {
        Some(Overlay::Theme { choice, previous }) => {
            assert_eq!(
                ThemeName::ALL[*choice],
                ThemeName::Ansi,
                "wrong starting row"
            );
            assert_eq!(
                *previous,
                ThemeName::Ansi,
                "previous is not what was drawing"
            );
        }
        other => panic!("no picker: {other:?}"),
    }

    let screen = frame(&mut app);
    let missing: Vec<&str> = ThemeName::ALL
        .iter()
        .map(|name| name.as_str())
        .filter(|name| !screen.contains(name))
        .collect();

    assert!(
        missing.is_empty(),
        "names missing: {missing:?}\n{}",
        screen.text()
    );
}
