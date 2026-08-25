//! Product-owned visual foundations for the native GPUI client.
//!
//! `gpui-component` owns interaction mechanics: focus, keyboard behavior, loading,
//! disabled states, and the shape of standard controls. This module owns Ouroboros's
//! visual policy and compositions. Feature code consumes semantic tokens from here so
//! it never needs to know which grey, radius, or status tint is active.

use gpui::prelude::*;
use gpui::{div, px, rgb, App, Div, ElementId, Hsla, Pixels, SharedString};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::tag::Tag;
use gpui_component::theme::{ActiveTheme as _, Theme, ThemeMode};
use gpui_component::{Icon, IconName, Sizable as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PaletteSpec {
    page: u32,
    canvas: u32,
    inset: u32,
    surface: u32,
    hover: u32,
    line: u32,
    ink: u32,
    ink_2: u32,
    accent: u32,
    accent_hover: u32,
    accent_tint: u32,
    success: u32,
    warning: u32,
    danger: u32,
}

const DARK: PaletteSpec = PaletteSpec {
    page: 0x17181a,
    canvas: 0x1c1d1f,
    inset: 0x1f2022,
    surface: 0x232427,
    hover: 0x2a2b2e,
    line: 0x2e3033,
    ink: 0xf2f3f4,
    ink_2: 0xa5a8ad,
    accent: 0x4fcb7d,
    accent_hover: 0x3fb96c,
    accent_tint: 0x203c2a,
    success: 0x62d295,
    warning: 0xf5b94c,
    danger: 0xf47777,
};

const LIGHT: PaletteSpec = PaletteSpec {
    page: 0xfafafb,
    canvas: 0xf1f2f3,
    inset: 0xf7f7f8,
    surface: 0xffffff,
    hover: 0xf4f5f6,
    line: 0xe2e4e7,
    ink: 0x1f2124,
    ink_2: 0x62656b,
    accent: 0x147a46,
    accent_hover: 0x0f693b,
    accent_tint: 0xe8f5ec,
    success: 0x168557,
    warning: 0x9a6400,
    danger: 0xce3f4a,
};

impl PaletteSpec {
    fn for_mode(mode: ThemeMode) -> Self {
        match mode {
            ThemeMode::Dark => DARK,
            ThemeMode::Light => LIGHT,
        }
    }
}

/// The small semantic vocabulary available to native Ouroboros views.
#[derive(Debug, Clone, Copy)]
pub struct DesktopTokens {
    pub page: Hsla,
    pub canvas: Hsla,
    pub inset: Hsla,
    pub surface: Hsla,
    pub hover: Hsla,
    pub line: Hsla,
    pub ink: Hsla,
    pub ink_2: Hsla,
    pub ink_3: Hsla,
    pub accent: Hsla,
    pub radius: Pixels,
    pub radius_lg: Pixels,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Accent,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, Copy)]
pub struct ToneColors {
    pub background: Hsla,
    pub border: Hsla,
    pub foreground: Hsla,
}

impl DesktopTokens {
    pub fn tone(self, cx: &App, tone: Tone) -> ToneColors {
        let theme = cx.theme();
        match tone {
            Tone::Neutral => ToneColors {
                background: self.surface,
                border: self.line,
                foreground: self.ink_2,
            },
            Tone::Accent => ToneColors {
                background: theme.selection,
                border: theme.primary.opacity(0.36),
                foreground: theme.primary,
            },
            Tone::Success => ToneColors {
                background: theme.success.opacity(0.10),
                border: theme.success.opacity(0.34),
                foreground: theme.success,
            },
            Tone::Warning => ToneColors {
                background: theme.warning.opacity(0.10),
                border: theme.warning.opacity(0.34),
                foreground: theme.warning,
            },
            Tone::Danger => ToneColors {
                background: theme.danger.opacity(0.10),
                border: theme.danger.opacity(0.34),
                foreground: theme.danger,
            },
        }
    }
}

fn hsla(value: u32) -> Hsla {
    rgb(value).into()
}

/// Align every gpui-component control with Ouroboros's semantic token contract.
pub fn install_component_theme(cx: &mut App) {
    let palette = PaletteSpec::for_mode(Theme::global(cx).mode);
    let dark = Theme::global(cx).mode.is_dark();
    let theme = Theme::global_mut(cx);

    theme.font_family = ".SystemUIFont".into();
    theme.font_size = px(14.0);
    theme.mono_font_size = px(12.0);
    theme.radius = px(8.0);
    theme.radius_lg = px(14.0);
    theme.shadow = false;
    theme.tile_shadow = false;
    theme.tile_radius = px(14.0);

    let colors = &mut theme.colors;
    colors.background = hsla(palette.page);
    colors.foreground = hsla(palette.ink);
    colors.border = hsla(palette.line);
    colors.input = hsla(palette.line);
    colors.caret = hsla(palette.accent);
    colors.ring = hsla(palette.accent);
    colors.selection = hsla(palette.accent_tint);
    colors.muted = hsla(palette.inset);
    colors.muted_foreground = hsla(palette.ink_2);
    colors.popover = hsla(palette.surface);
    colors.popover_foreground = hsla(palette.ink);

    colors.primary = hsla(palette.accent);
    colors.primary_hover = hsla(palette.accent_hover);
    colors.primary_active = hsla(palette.accent_hover);
    colors.primary_foreground = hsla(0xffffff);
    colors.secondary = hsla(palette.surface);
    colors.secondary_hover = hsla(palette.hover);
    colors.secondary_active = hsla(palette.inset);
    colors.secondary_foreground = hsla(palette.ink);
    colors.accent = hsla(palette.hover);
    colors.accent_foreground = hsla(palette.ink);

    colors.sidebar = hsla(palette.canvas);
    colors.sidebar_foreground = hsla(palette.ink);
    colors.sidebar_border = hsla(palette.line);
    colors.sidebar_accent = hsla(palette.surface);
    colors.sidebar_accent_foreground = hsla(palette.ink);
    colors.sidebar_primary = hsla(palette.accent);
    colors.sidebar_primary_foreground = hsla(0xffffff);

    // gpui-component semantic colors are base hues. The components derive their own
    // translucent fills; storing tints here makes Alerts and Buttons visually incorrect.
    colors.info = hsla(palette.accent);
    colors.info_hover = hsla(palette.accent_hover);
    colors.info_active = hsla(palette.accent_hover);
    colors.info_foreground = hsla(0xffffff);
    colors.success = hsla(palette.success);
    colors.success_hover = hsla(palette.success).opacity(0.86);
    colors.success_active = hsla(palette.success).opacity(0.76);
    colors.success_foreground = hsla(0xffffff);
    colors.warning = hsla(palette.warning);
    colors.warning_hover = hsla(palette.warning).opacity(0.86);
    colors.warning_active = hsla(palette.warning).opacity(0.76);
    colors.warning_foreground = if dark { hsla(0x17181a) } else { hsla(0xffffff) };
    colors.danger = hsla(palette.danger);
    colors.danger_hover = hsla(palette.danger).opacity(0.86);
    colors.danger_active = hsla(palette.danger).opacity(0.76);
    colors.danger_foreground = hsla(0xffffff);

    colors.title_bar = hsla(palette.page);
    colors.title_bar_border = hsla(palette.line);
    colors.scrollbar = hsla(palette.page);
    colors.scrollbar_thumb = hsla(palette.line);
    colors.scrollbar_thumb_hover = hsla(palette.ink_2);
    colors.progress_bar = hsla(palette.accent);
    colors.skeleton = hsla(palette.hover);
    colors.overlay = hsla(palette.canvas);
}

/// Resolve feature-facing tokens from the active gpui-component theme.
pub fn tokens(cx: &App) -> DesktopTokens {
    let theme = cx.theme();
    DesktopTokens {
        page: theme.background,
        canvas: theme.sidebar,
        inset: theme.muted,
        surface: theme.secondary,
        hover: theme.accent,
        line: theme.border,
        ink: theme.foreground,
        ink_2: theme.muted_foreground,
        ink_3: theme
            .muted_foreground
            .opacity(if theme.is_dark() { 0.62 } else { 0.72 }),
        accent: theme.primary,
        radius: theme.radius,
        radius_lg: theme.radius_lg,
    }
}

pub fn panel(tokens: DesktopTokens) -> Div {
    div()
        .rounded(tokens.radius_lg)
        .bg(tokens.surface)
        .border_1()
        .border_color(tokens.line)
}

pub fn card(tokens: DesktopTokens, cx: &App, tone: Tone) -> Div {
    let colors = tokens.tone(cx, tone);
    div()
        .rounded(tokens.radius)
        .bg(colors.background)
        .border_1()
        .border_color(colors.border)
}

pub fn inset(tokens: DesktopTokens) -> Div {
    div()
        .rounded(tokens.radius)
        .bg(tokens.inset)
        .border_1()
        .border_color(tokens.line)
}

pub fn status_tag(
    tokens: DesktopTokens,
    cx: &App,
    tone: Tone,
    label: impl Into<SharedString>,
) -> Tag {
    let colors = tokens.tone(cx, tone);
    Tag::custom(colors.background, colors.foreground, colors.border)
        .small()
        .rounded_full()
        .child(label.into())
}

pub fn eyebrow(tokens: DesktopTokens, label: impl Into<SharedString>) -> Div {
    div()
        .text_xs()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(tokens.ink_3)
        .child(label.into())
}

pub fn keycap(tokens: DesktopTokens, label: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .items_center()
        .h_5()
        .px_1p5()
        .rounded(tokens.radius / 2.0)
        .bg(tokens.inset)
        .border_1()
        .border_color(tokens.line)
        .text_xs()
        .font_family("monospace")
        .text_color(tokens.ink_2)
        .child(label.into())
}

pub fn icon_tile(tokens: DesktopTokens, cx: &App, tone: Tone, icon: IconName) -> Div {
    let colors = tokens.tone(cx, tone);
    div()
        .flex()
        .items_center()
        .justify_center()
        .size_8()
        .flex_none()
        .rounded(tokens.radius)
        .bg(colors.background)
        .border_1()
        .border_color(colors.border)
        .text_color(colors.foreground)
        .child(Icon::new(icon).small())
}

pub fn empty_state(
    tokens: DesktopTokens,
    cx: &App,
    icon: IconName,
    title: impl Into<SharedString>,
    body: impl Into<SharedString>,
) -> Div {
    div()
        .flex()
        .flex_col()
        .items_center()
        .text_center()
        .gap_2()
        .w_full()
        .max_w(px(440.0))
        .px_6()
        .py_8()
        .child(icon_tile(tokens, cx, Tone::Accent, icon))
        .child(
            div()
                .mt_2()
                .text_lg()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .text_color(tokens.ink)
                .child(title.into()),
        )
        .child(div().text_sm().text_color(tokens.ink_2).child(body.into()))
}

pub fn field(
    tokens: DesktopTokens,
    label: impl Into<SharedString>,
    hint: Option<SharedString>,
    control: impl IntoElement,
) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .text_sm()
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child(label.into()),
                )
                .when_some(hint, |row, hint| {
                    row.child(div().text_xs().text_color(tokens.ink_3).child(hint))
                }),
        )
        .child(control)
}

pub fn primary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).small().primary().label(label)
}

pub fn secondary_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).small().label(label)
}

pub fn danger_button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Button {
    Button::new(id).small().danger().outline().label(label)
}

pub fn icon_button(
    id: impl Into<ElementId>,
    icon: IconName,
    tooltip: impl Into<SharedString>,
) -> Button {
    Button::new(id).small().ghost().icon(icon).tooltip(tooltip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palettes_keep_the_same_semantic_layer_order() {
        assert!(DARK.page < DARK.canvas);
        assert!(DARK.canvas < DARK.surface);
        assert!(LIGHT.page > LIGHT.canvas);
        assert!(LIGHT.surface > LIGHT.canvas);
        assert_ne!(DARK.line, DARK.surface);
        assert_ne!(LIGHT.line, LIGHT.surface);
    }

    #[test]
    fn semantic_hues_do_not_reuse_the_action_accent() {
        for palette in [DARK, LIGHT] {
            assert_ne!(palette.warning, palette.accent);
            assert_ne!(palette.danger, palette.accent);
            assert_ne!(palette.success, palette.accent);
        }
    }

    #[test]
    fn action_accent_is_green_in_every_mode() {
        for palette in [DARK, LIGHT] {
            let red = (palette.accent >> 16) & 0xff;
            let green = (palette.accent >> 8) & 0xff;
            let blue = palette.accent & 0xff;
            assert!(green > red);
            assert!(green > blue);
        }
    }
}
