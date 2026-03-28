#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod scanner;
#[path = "../RSS-Journal/usn_journal.rs"]
mod usn_journal;
#[allow(dead_code)]
mod viewer;

use chrono::Local;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, FontData, FontDefinitions, FontFamily, Frame, Key, KeyboardShortcut,
    Layout, Margin, Modifiers, RichText, Sense, Stroke,
};

const APP_TITLE: &str = "RSS-AltsChecker";
const WINDOW_SIZE: [f32; 2] = [1060.0, 740.0];
const WINDOW_MIN_SIZE: [f32; 2] = [860.0, 600.0];
const CONTENT_MAX_WIDTH: f32 = 1040.0;
const EVENTS_MIN_VISIBLE_HEIGHT: f32 = 300.0;
const EVENTS_MAX_VISIBLE_HEIGHT: f32 = 620.0;
const MIN_ZOOM_FACTOR: f32 = 0.7;
const MAX_ZOOM_FACTOR: f32 = 1.8;
const TOAST_VISIBLE_MS: u64 = 1650;
const UI_STROKE_WIDTH: f32 = 0.75;
const APP_BAR_DIVIDER_WIDTH: f32 = 0.8;
const APP_BAR_LIGHT_DIVIDER_WIDTH: f32 = 1.0;
const CENTER_CARD_WIDTH: f32 = 360.0;
const CENTER_CARD_HEIGHT: f32 = 132.0;
const LOADING_TRANSITION_SECONDS: f32 = 0.30;
const FONT_BODY: &str = "roboto_body";
const FONT_HEADING: &str = "roboto_heading";
const HEADING_FAMILY: &str = "heading_family";

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusState {
    Idle,
    Scanning,
    Done,
    Error,
}

#[derive(Clone, Copy)]
struct UiPalette {
    background: Color32,
    topbar: Color32,
    surface: Color32,
    surface_alt: Color32,
    border: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    accent_hover: Color32,
    danger: Color32,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(APP_TITLE)
        .with_inner_size(WINDOW_SIZE)
        .with_min_inner_size(WINDOW_MIN_SIZE);

    if let Some(icon) = load_icon_data() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|creation_context| Ok(Box::new(RssAltsCheckerApp::new(creation_context)))),
    )
    .map_err(|error| format!("Failed to start GUI: {error}"))
}

struct RssAltsCheckerApp {
    report: Option<scanner::ScanReport>,
    status_line: String,
    status_state: StatusState,
    error_message: Option<String>,
    is_scanning: bool,
    has_started: bool,
    receiver: Option<Receiver<Result<scanner::ScanReport, String>>>,
    cancel_flag: Option<Arc<AtomicBool>>,
    event_log: Vec<String>,
    ghost_mode: bool,
    is_dark_theme: bool,
    toast_message: Option<String>,
    toast_deadline: Option<Instant>,
}

impl RssAltsCheckerApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        let is_dark_theme = true;
        setup_fonts(&context.egui_ctx);
        apply_theme(&context.egui_ctx, is_dark_theme);

        let mut app = Self {
            report: None,
            status_line: String::new(),
            status_state: StatusState::Idle,
            error_message: None,
            is_scanning: false,
            has_started: false,
            receiver: None,
            cancel_flag: None,
            event_log: Vec::new(),
            ghost_mode: false,
            is_dark_theme,
            toast_message: None,
            toast_deadline: None,
        };
        app.push_event("Приложение запущено");
        app
    }

    fn push_event(&mut self, message: impl Into<String>) {
        let line = format!("{}  {}", Local::now().format("%H:%M:%S"), message.into());
        self.event_log.push(line);
    }

    fn palette(&self) -> UiPalette {
        palette(self.is_dark_theme)
    }

    fn show_success_toast(&mut self, message: impl Into<String>) {
        self.toast_message = Some(message.into());
        self.toast_deadline = Some(Instant::now() + Duration::from_millis(TOAST_VISIBLE_MS));
    }

    fn ui_toast(&mut self, context: &egui::Context) {
        let Some(deadline) = self.toast_deadline else {
            return;
        };
        if Instant::now() > deadline {
            self.toast_message = None;
            self.toast_deadline = None;
            return;
        }

        let Some(message) = self.toast_message.as_ref() else {
            return;
        };

        let colors = self.palette();
        egui::Area::new(egui::Id::new("success_toast"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-14.0, 70.0))
            .show(context, |ui| {
                Frame::new()
                    .fill(Color32::from_rgba_premultiplied(
                        colors.accent.r(),
                        colors.accent.g(),
                        colors.accent.b(),
                        56,
                    ))
                    .stroke(Stroke::new(UI_STROKE_WIDTH, colors.accent_hover))
                    .corner_radius(egui::CornerRadius::same(9))
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(message)
                                .size(12.5)
                                .strong()
                                .color(Color32::WHITE),
                        );
                    });
            });
    }

    fn start_scan(&mut self) {
        if self.is_scanning {
            return;
        }

        self.has_started = true;
        self.is_scanning = true;
        self.report = None;
        self.error_message = None;
        self.status_state = StatusState::Scanning;
        self.status_line = "Сканирование...".to_string();
        self.push_event("Запущено сканирование Minecraft + Discord");

        let cancel_flag = Arc::new(AtomicBool::new(false));
        self.cancel_flag = Some(cancel_flag.clone());

        let options = scanner::ScanOptions {
            cancel_flag: Some(cancel_flag),
            ..scanner::ScanOptions::default()
        };

        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);

        thread::spawn(move || {
            let result = scanner::run_scan(&options);
            let _ = sender.send(result);
        });
    }

    fn poll_background_scan(&mut self) {
        let Some(receiver) = self.receiver.as_ref() else {
            return;
        };

        let Ok(result) = receiver.try_recv() else {
            return;
        };

        self.receiver = None;
        self.cancel_flag = None;
        self.is_scanning = false;

        match result {
            Ok(report) => {
                let discord_count = report.discord_accounts.len();
                let minecraft_count = report.minecraft_accounts.len();

                self.status_state = StatusState::Done;
                self.status_line = format!(
                    "Готово: Discord {} | Minecraft {}",
                    discord_count, minecraft_count
                );
                self.error_message = None;
                self.push_event(format!(
                    "Сканирование завершено: Discord {} | Minecraft {}",
                    discord_count, minecraft_count
                ));

                if let Some(usn) = &report.usn_journal {
                    if usn.status.to_ascii_lowercase().starts_with("usn") {
                        self.push_event(format!(
                            "{} | records {}",
                            usn.status, usn.scanned_records
                        ));
                    } else {
                        self.push_event(format!(
                            "USN: {} | records {}",
                            usn.status, usn.scanned_records
                        ));
                    }
                }

                for signal in &report.forensic_signals {
                    self.push_event(signal.clone());
                }

                if !report.warnings.is_empty() {
                    self.push_event(format!(
                        "Предупреждений при сканировании: {}",
                        report.warnings.len()
                    ));
                    for warning in &report.warnings {
                        self.push_event(format!("Warning: {warning}"));
                    }
                }

                self.report = Some(report);
            }
            Err(error) => {
                if scanner::is_cancelled_error(&error) {
                    self.status_state = StatusState::Idle;
                    self.status_line = scanner::SCAN_CANCELLED_MESSAGE.to_string();
                    self.error_message = None;
                    self.push_event("Сканирование остановлено пользователем");
                    return;
                }

                self.status_state = StatusState::Error;
                self.status_line = "Ошибка сканирования".to_string();
                self.error_message = Some(error.clone());
                self.push_event(format!("Ошибка: {error}"));
            }
        }
    }

    fn ui_app_bar(&mut self, context: &egui::Context) {
        let colors = self.palette();
        let panel = egui::TopBottomPanel::top("app_bar")
            .show_separator_line(false)
            .exact_height(56.0)
            .frame(
                Frame::new()
                    .fill(colors.topbar)
                    .inner_margin(Margin::symmetric(16, 8))
                    .stroke(Stroke::NONE),
            )
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    let title_response = ui.label(
                        RichText::new(APP_TITLE)
                            .strong()
                            .size(22.0)
                            .family(FontFamily::Name(HEADING_FAMILY.into()))
                            .color(colors.text),
                    );
                    if !self.status_line.is_empty() {
                        title_response.on_hover_text(&self.status_line);
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let theme_button = egui::Button::new("")
                            .min_size(egui::vec2(34.0, 34.0))
                            .fill(colors.surface_alt)
                            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border));
                        let response = ui.add(theme_button);
                        let painter = ui.painter();
                        let center = response.rect.center();
                        let icon_color = colors.text;

                        if self.is_dark_theme {
                            let radius = 4.6;
                            painter.circle_filled(center, radius, icon_color);
                            for i in 0..8 {
                                let angle = (i as f32 / 8.0) * std::f32::consts::TAU;
                                let dir = egui::vec2(angle.cos(), angle.sin());
                                painter.line_segment(
                                    [center + dir * (radius + 2.0), center + dir * (radius + 5.0)],
                                    Stroke::new(1.2, icon_color),
                                );
                            }
                        } else {
                            let radius = 6.4;
                            painter.circle_filled(center, radius, icon_color);
                            painter.circle_filled(
                                center + egui::vec2(2.6, -1.7),
                                radius,
                                colors.surface_alt,
                            );
                        }

                        if response.clicked() {
                            self.is_dark_theme = !self.is_dark_theme;
                            apply_theme(context, self.is_dark_theme);
                        }
                        response.on_hover_text("Переключить тему");
                    });
                });
            });

        let rect = panel.response.rect;
        let (divider, divider_width) = if self.is_dark_theme {
            (
                Color32::from_rgba_premultiplied(
                    colors.border.r(),
                    colors.border.g(),
                    colors.border.b(),
                    185,
                ),
                APP_BAR_DIVIDER_WIDTH,
            )
        } else {
            // Higher-contrast divider for light theme so the app bar edge is always visible.
            (
                Color32::from_rgb(157, 167, 183),
                APP_BAR_LIGHT_DIVIDER_WIDTH,
            )
        };
        let y = rect.bottom() - 0.5;
        context
            .layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("app_bar_bottom_divider"),
            ))
            .line_segment(
                [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                Stroke::new(divider_width, divider),
            );
    }

    fn ui_start_screen(&mut self, ui: &mut egui::Ui) {
        let colors = self.palette();
        ui.vertical_centered(|ui| {
            let top_space = ((ui.available_height() - CENTER_CARD_HEIGHT) * 0.5).max(16.0);
            ui.add_space(top_space);

            Frame::new()
                .fill(colors.surface)
                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                .corner_radius(egui::CornerRadius::same(12))
                .inner_margin(Margin::symmetric(18, 14))
                .show(ui, |ui| {
                    ui.set_width(CENTER_CARD_WIDTH);
                    ui.set_min_height(CENTER_CARD_HEIGHT);
                    ui.vertical_centered(|ui| {
                        let button = egui::Button::new(
                            RichText::new("Начать сканирование")
                                .strong()
                                .size(15.0)
                                .color(Color32::WHITE),
                        )
                        .min_size(egui::vec2(CENTER_CARD_WIDTH - 52.0, 40.0))
                        .fill(colors.accent)
                        .stroke(Stroke::new(UI_STROKE_WIDTH, colors.accent_hover));

                        if ui.add(button).clicked() {
                            self.start_scan();
                        }

                        ui.add_space(12.0);
                        let ghost_label = if self.ghost_mode {
                            "Ghost mode: ON"
                        } else {
                            "Ghost mode: OFF"
                        };
                        let ghost_button = egui::Button::new(
                            RichText::new(ghost_label).size(12.0).color(colors.text),
                        )
                        .min_size(egui::vec2(176.0, 34.0))
                        .fill(if self.ghost_mode {
                            Color32::from_rgba_premultiplied(
                                colors.accent.r(),
                                colors.accent.g(),
                                colors.accent.b(),
                                38,
                            )
                        } else {
                            colors.surface_alt
                        })
                        .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border));
                        if ui.add(ghost_button).clicked() {
                            self.ghost_mode = !self.ghost_mode;
                            if self.ghost_mode {
                                self.push_event("Включен режим ghost mode");
                            } else {
                                self.push_event("Выключен режим ghost mode");
                            }
                        }
                    });
                });
        });
    }

    fn ui_loading_screen(&self, context: &egui::Context, ui: &mut egui::Ui) {
        let colors = self.palette();
        let progress = context.animate_bool_with_time_and_easing(
            egui::Id::new("loading_screen_transition"),
            self.is_scanning,
            LOADING_TRANSITION_SECONDS,
            egui::emath::easing::cubic_out,
        );
        let slide_offset = (1.0 - progress) * 14.0;
        let fill_alpha = (200.0 + 55.0 * progress).round().clamp(0.0, 255.0) as u8;
        let text_alpha = progress.clamp(0.15, 1.0);

        ui.vertical_centered(|ui| {
            let top_space =
                ((ui.available_height() - CENTER_CARD_HEIGHT) * 0.5 + slide_offset).max(16.0);
            ui.add_space(top_space);

            Frame::new()
                .fill(Color32::from_rgba_premultiplied(
                    colors.surface.r(),
                    colors.surface.g(),
                    colors.surface.b(),
                    fill_alpha,
                ))
                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                .corner_radius(egui::CornerRadius::same(12))
                .inner_margin(Margin::symmetric(18, 14))
                .show(ui, |ui| {
                    ui.set_width(CENTER_CARD_WIDTH);
                    ui.set_min_height(CENTER_CARD_HEIGHT);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new("Идёт сканирование")
                                .strong()
                                .size(24.0)
                                .family(FontFamily::Name(HEADING_FAMILY.into()))
                                .color(colors.text.gamma_multiply(text_alpha)),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("Сканирование источников, подождите...")
                                .size(13.0)
                                .color(colors.muted.gamma_multiply(text_alpha)),
                        );
                        ui.add_space(14.0);
                        ui.add(
                            egui::Spinner::new()
                                .size(22.0 + 10.0 * progress)
                                .color(colors.accent.gamma_multiply(text_alpha)),
                        );
                    });
                });
        });
    }

    fn ui_accounts_panel(&mut self, ui: &mut egui::Ui) {
        let colors = self.palette();

        Frame::new()
            .fill(colors.surface)
            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                let Some(report) = self.report.as_ref() else {
                    ui.label(
                        RichText::new("Нет данных сканирования")
                            .size(14.0)
                            .color(colors.muted),
                    );
                    return;
                };

                if self.ghost_mode {
                    ui.label(
                        RichText::new("Включен режим ghost mode, анализируйте json вручную")
                            .size(15.0)
                            .color(colors.muted),
                    );
                    return;
                }

                let mut pending_toast: Option<String> = None;
                ui.horizontal_wrapped(|ui| {
                    let copy_mc = egui::Button::new(
                        RichText::new("Copy Minecraft")
                            .size(12.5)
                            .color(Color32::WHITE),
                    )
                    .fill(colors.accent)
                    .stroke(Stroke::new(UI_STROKE_WIDTH, colors.accent_hover))
                    .min_size(egui::vec2(138.0, 32.0));
                    if ui.add(copy_mc).clicked() {
                        ui.ctx()
                            .copy_text(Self::build_minecraft_copy_text(&report.minecraft_accounts));
                        pending_toast = Some("Успешно: Minecraft ники скопированы".to_string());
                    }

                    let copy_dc = egui::Button::new(
                        RichText::new("Copy Discord")
                            .size(12.5)
                            .color(Color32::WHITE),
                    )
                    .fill(colors.accent)
                    .stroke(Stroke::new(UI_STROKE_WIDTH, colors.accent_hover))
                    .min_size(egui::vec2(122.0, 32.0));
                    if ui.add(copy_dc).clicked() {
                        ui.ctx()
                            .copy_text(Self::build_discord_copy_text(&report.discord_accounts));
                        pending_toast = Some("Успешно: Discord ники скопированы".to_string());
                    }

                    let copy_all =
                        egui::Button::new(RichText::new("Copy all").size(12.5).color(colors.text))
                            .fill(colors.surface_alt)
                            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                            .min_size(egui::vec2(100.0, 32.0));
                    if ui.add(copy_all).clicked() {
                        ui.ctx().copy_text(Self::build_all_copy_text(report));
                        pending_toast = Some("Успешно: всё скопировано".to_string());
                    }
                });
                ui.add_space(10.0);

                ui.columns(2, |columns| {
                    self.render_minecraft_column(&mut columns[0], report, colors);
                    self.render_discord_column(&mut columns[1], report, colors);
                });

                if let Some(message) = pending_toast {
                    self.show_success_toast(message);
                }
            });
    }

    fn build_minecraft_copy_text(accounts: &[scanner::MinecraftAlt]) -> String {
        if accounts.is_empty() {
            return String::new();
        }
        accounts
            .iter()
            .map(|account| account.username.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn build_discord_copy_text(accounts: &[scanner::DiscordAlt]) -> String {
        if accounts.is_empty() {
            return String::new();
        }
        accounts
            .iter()
            .map(|account| account.username.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn build_all_copy_text(report: &scanner::ScanReport) -> String {
        let minecraft = Self::build_minecraft_copy_text(&report.minecraft_accounts);
        let discord = Self::build_discord_copy_text(&report.discord_accounts);
        format!("Minecraft Nick:\n{minecraft}\n\nDiscord Nick:\n{discord}")
    }

    fn handle_zoom_controls(&self, context: &egui::Context) {
        context.options_mut(|options| {
            options.zoom_with_keyboard = false;
        });

        let mut reset = false;
        let mut keyboard_step = 0.0f32;

        context.input_mut(|input| {
            if input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::Num0)) {
                reset = true;
                return;
            }
            if input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::Plus))
                || input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::Equals))
            {
                keyboard_step += 0.1;
            }
            if input.consume_shortcut(&KeyboardShortcut::new(Modifiers::COMMAND, Key::Minus)) {
                keyboard_step -= 0.1;
            }
        });

        if reset {
            context.set_zoom_factor(1.0);
            return;
        }

        let wheel_delta = context.input(|input| input.zoom_delta());
        let mut target = context.zoom_factor();
        if keyboard_step.abs() > f32::EPSILON {
            target += keyboard_step;
        }
        if (wheel_delta - 1.0).abs() > f32::EPSILON {
            target *= wheel_delta;
        }

        target = (target * 10.0).round() / 10.0;
        target = target.clamp(MIN_ZOOM_FACTOR, MAX_ZOOM_FACTOR);

        if (target - context.zoom_factor()).abs() > 0.001 {
            context.set_zoom_factor(target);
        }
    }

    fn source_label(count: usize) -> String {
        if count == 1 {
            "1 source".to_string()
        } else {
            format!("{count} sources")
        }
    }

    fn compact_source_path(path: &str, tail_components: usize) -> String {
        let components = Path::new(path)
            .components()
            .filter_map(|component| match component {
                std::path::Component::Prefix(prefix) => {
                    Some(prefix.as_os_str().to_string_lossy().to_string())
                }
                std::path::Component::Normal(value) => Some(value.to_string_lossy().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();

        if components.is_empty() {
            return path.to_string();
        }
        if components.len() <= tail_components {
            return components.join("\\");
        }

        let tail_start = components.len().saturating_sub(tail_components);
        format!("...\\{}", components[tail_start..].join("\\"))
    }

    fn preview_list(items: &[String], max_items: usize) -> String {
        if items.is_empty() {
            return String::new();
        }
        if items.len() <= max_items {
            return items.join(", ");
        }
        let head = items[..max_items].join(", ");
        format!("{head}, +{} more", items.len() - max_items)
    }

    fn humanize_minecraft_reason(reason: &str) -> String {
        if let Some((account_hits, log_hits)) = parse_trusted_reason(reason) {
            return format!("Подтверждено account-файлами: {account_hits}; логами: {log_hits}");
        }

        if let Some(value) = parse_reason_suffix_usize(reason, "log-evidence:") {
            return format!("Подтверждено логами: {value}");
        }
        if let Some(value) = parse_reason_suffix_usize(reason, "placeholder-multi-log:") {
            return format!("Плейсхолдер, но подтверждено многими логами: {value}");
        }
        if let Some(value) = parse_reason_suffix_usize(reason, "placeholder-filtered:") {
            return format!("Отфильтрован как плейсхолдер (логов: {value})");
        }
        if reason == "structural-word-filter" {
            return "Отфильтрован как системное/структурное слово".to_string();
        }
        if reason == "no-usable-evidence" {
            return "Недостаточно доказательств для включения".to_string();
        }

        reason.to_string()
    }

    fn render_minecraft_column(
        &self,
        ui: &mut egui::Ui,
        report: &scanner::ScanReport,
        colors: UiPalette,
    ) {
        Frame::new()
            .fill(colors.surface_alt)
            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(Margin::same(12))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("Minecraft ({})", report.minecraft_accounts.len()))
                        .strong()
                        .size(20.0)
                        .family(FontFamily::Name(HEADING_FAMILY.into()))
                        .color(colors.text),
                );
                ui.add_space(8.0);

                if report.minecraft_accounts.is_empty() {
                    ui.label(
                        RichText::new("Аккаунты не найдены")
                            .italics()
                            .size(13.0)
                            .color(colors.muted),
                    );
                    return;
                }

                for account in &report.minecraft_accounts {
                    let title = format!(
                        "{}  [{}]",
                        account.username,
                        Self::source_label(account.sources.len())
                    );
                    Frame::new()
                        .fill(colors.surface)
                        .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                        .corner_radius(egui::CornerRadius::same(8))
                        .inner_margin(Margin::symmetric(8, 7))
                        .show(ui, |ui| {
                            egui::CollapsingHeader::new(
                                RichText::new(title).size(14.0).color(colors.text),
                            )
                            .id_salt(("mc_account", account.username.as_str()))
                            .default_open(false)
                            .show(ui, |ui| {
                                if let Some(debug) =
                                    report.minecraft_detection_debug.iter().find(|item| {
                                        item.username.eq_ignore_ascii_case(&account.username)
                                    })
                                {
                                    let readable_reason =
                                        Self::humanize_minecraft_reason(&debug.reason);
                                    ui.label(
                                        RichText::new(format!("Reason: {}", readable_reason))
                                            .size(12.2)
                                            .strong()
                                            .color(colors.text),
                                    );
                                    if debug.reason != readable_reason {
                                        ui.label(
                                            RichText::new(format!("Raw: {}", debug.reason))
                                                .size(11.3)
                                                .monospace()
                                                .color(colors.muted),
                                        );
                                    }
                                    ui.add_space(4.0);
                                }

                                Self::render_sources_block(ui, &account.sources, colors);
                                Self::render_minecraft_links_block(
                                    ui,
                                    report,
                                    &account.username,
                                    colors,
                                );
                            });
                        });
                    ui.add_space(7.0);
                }
            });
    }

    fn render_discord_column(
        &self,
        ui: &mut egui::Ui,
        report: &scanner::ScanReport,
        colors: UiPalette,
    ) {
        Frame::new()
            .fill(colors.surface_alt)
            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(Margin::same(12))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("Discord ({})", report.discord_accounts.len()))
                        .strong()
                        .size(20.0)
                        .family(FontFamily::Name(HEADING_FAMILY.into()))
                        .color(colors.text),
                );
                ui.add_space(8.0);

                if report.discord_accounts.is_empty() {
                    ui.label(
                        RichText::new("Аккаунты не найдены")
                            .italics()
                            .size(13.0)
                            .color(colors.muted),
                    );
                    return;
                }

                for account in &report.discord_accounts {
                    let id = account.id.clone().unwrap_or_else(|| "unknown".to_string());
                    let title = format!(
                        "{} ({id})  [{}]",
                        account.username,
                        Self::source_label(account.sources.len())
                    );
                    Frame::new()
                        .fill(colors.surface)
                        .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                        .corner_radius(egui::CornerRadius::same(8))
                        .inner_margin(Margin::symmetric(8, 7))
                        .show(ui, |ui| {
                            egui::CollapsingHeader::new(
                                RichText::new(title).size(14.0).color(colors.text),
                            )
                            .id_salt((
                                "discord_account",
                                account.username.as_str(),
                                account.id.as_deref().unwrap_or("unknown"),
                            ))
                            .default_open(false)
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(format!("ID: {id}"))
                                        .size(12.2)
                                        .strong()
                                        .color(colors.text),
                                );
                                Self::render_sources_block(ui, &account.sources, colors);
                                Self::render_discord_links_block(ui, report, account, colors);
                            });
                        });
                    ui.add_space(7.0);
                }
            });
    }

    fn render_sources_block(ui: &mut egui::Ui, sources: &[String], colors: UiPalette) {
        if sources.is_empty() {
            return;
        }

        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("Sources: {}", sources.len()))
                .size(12.0)
                .strong()
                .color(colors.text),
        );
        for (index, source) in sources.iter().enumerate() {
            let compact = Self::compact_source_path(source, 4);
            Frame::new()
                .fill(colors.surface_alt)
                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                .corner_radius(egui::CornerRadius::same(7))
                .inner_margin(Margin::symmetric(9, 7))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let response = ui.add(
                            egui::Label::new(
                                RichText::new(format!("{}.", index + 1))
                                    .size(11.5)
                                    .monospace()
                                    .color(colors.muted),
                            )
                            .sense(Sense::click()),
                        );
                        if response.clicked() {
                            ui.ctx().copy_text(source.clone());
                        }
                        response.on_hover_text(format!("{}\nClick: copy full path", source));

                        ui.add(
                            egui::Label::new(
                                RichText::new(compact)
                                    .size(11.5)
                                    .monospace()
                                    .color(colors.text),
                            )
                            .wrap(),
                        );
                    });
                });
            ui.add_space(5.0);
        }
    }

    fn render_minecraft_links_block(
        ui: &mut egui::Ui,
        report: &scanner::ScanReport,
        username: &str,
        colors: UiPalette,
    ) {
        let related = report
            .profile_links
            .iter()
            .filter(|link| {
                link.minecraft_accounts
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(username))
            })
            .collect::<Vec<_>>();

        if related.is_empty() {
            return;
        }

        ui.add_space(4.0);
        ui.label(
            RichText::new("Linked Profiles:")
                .size(12.0)
                .strong()
                .color(colors.text),
        );

        for link in related {
            let title = format!(
                "{}  |  Minecraft: {}",
                link.profile,
                link.minecraft_accounts.len()
            );
            Frame::new()
                .fill(colors.surface_alt)
                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                .corner_radius(egui::CornerRadius::same(7))
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    egui::CollapsingHeader::new(
                        RichText::new(title)
                            .size(12.0)
                            .monospace()
                            .color(colors.text),
                    )
                    .id_salt(("mc_profile_link", username, link.profile.as_str()))
                    .default_open(false)
                    .show(ui, |ui| {
                        if !link.minecraft_accounts.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "Minecraft: {}",
                                        Self::preview_list(&link.minecraft_accounts, 8)
                                    ))
                                    .size(11.5)
                                    .color(colors.text),
                                )
                                .wrap(),
                            );
                        }
                    });
                });
            ui.add_space(5.0);
        }
    }

    fn render_discord_links_block(
        ui: &mut egui::Ui,
        report: &scanner::ScanReport,
        account: &scanner::DiscordAlt,
        colors: UiPalette,
    ) {
        let related = report
            .profile_links
            .iter()
            .filter(|link| {
                link.discord_accounts
                    .iter()
                    .any(|name| Self::discord_link_matches_account(name, account))
            })
            .collect::<Vec<_>>();

        if related.is_empty() {
            return;
        }

        ui.add_space(4.0);
        ui.label(
            RichText::new("Linked Profiles:")
                .size(12.0)
                .strong()
                .color(colors.text),
        );

        for link in related {
            let title = format!(
                "{}  |  Discord: {}",
                link.profile,
                link.discord_accounts.len()
            );
            Frame::new()
                .fill(colors.surface_alt)
                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                .corner_radius(egui::CornerRadius::same(7))
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    egui::CollapsingHeader::new(
                        RichText::new(title)
                            .size(12.0)
                            .monospace()
                            .color(colors.text),
                    )
                    .id_salt((
                        "discord_profile_link",
                        account.id.as_deref().unwrap_or("unknown"),
                        link.profile.as_str(),
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        if !link.discord_accounts.is_empty() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "Discord: {}",
                                        Self::preview_list(&link.discord_accounts, 6)
                                    ))
                                    .size(11.5)
                                    .color(colors.text),
                                )
                                .wrap(),
                            );
                        }
                    });
                });
            ui.add_space(5.0);
        }
    }

    fn discord_link_matches_account(link_value: &str, account: &scanner::DiscordAlt) -> bool {
        if link_value.eq_ignore_ascii_case(&account.username) {
            return true;
        }

        if let Some(id) = &account.id {
            if link_value.eq_ignore_ascii_case(id)
                || link_value.eq_ignore_ascii_case(&format!("id:{id}"))
            {
                return true;
            }
        }

        false
    }

    fn ui_events_panel(&self, ui: &mut egui::Ui) {
        let colors = self.palette();

        Frame::new()
            .fill(colors.surface)
            .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.label(
                    RichText::new("Журнал событий")
                        .strong()
                        .size(20.0)
                        .family(FontFamily::Name(HEADING_FAMILY.into()))
                        .color(colors.text),
                );
                ui.add_space(8.0);

                if self.event_log.is_empty() {
                    ui.label(
                        RichText::new("Событий пока нет")
                            .size(13.0)
                            .color(colors.muted),
                    );
                    return;
                }

                egui::ScrollArea::vertical()
                    .max_height(EVENTS_MAX_VISIBLE_HEIGHT)
                    .min_scrolled_height(EVENTS_MIN_VISIBLE_HEIGHT)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in self.event_log.iter().rev() {
                            let color = event_line_color(line, colors);
                            Frame::new()
                                .fill(colors.surface_alt)
                                .stroke(Stroke::new(UI_STROKE_WIDTH, colors.border))
                                .corner_radius(egui::CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(8, 6))
                                .show(ui, |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(line).size(12.5).monospace().color(color),
                                        )
                                        .wrap(),
                                    );
                                });
                            ui.add_space(4.0);
                        }
                    });
            });
    }

    fn ui_main_content(&mut self, context: &egui::Context) {
        let colors = self.palette();

        egui::CentralPanel::default()
            .frame(Frame::new().fill(colors.background))
            .show(context, |ui| {
                if self.is_scanning {
                    self.ui_loading_screen(context, ui);
                    return;
                }

                if !self.has_started {
                    self.ui_start_screen(ui);
                    return;
                }

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(14.0);

                        let width = CONTENT_MAX_WIDTH.min(ui.available_width());
                        ui.horizontal(|ui| {
                            let side = ((ui.available_width() - width) * 0.5).max(0.0);
                            if side > 0.0 {
                                ui.add_space(side);
                            }

                            ui.vertical(|ui| {
                                ui.set_width(width);

                                if let Some(error) = &self.error_message {
                                    Frame::new()
                                        .fill(Color32::from_rgba_premultiplied(
                                            colors.danger.r(),
                                            colors.danger.g(),
                                            colors.danger.b(),
                                            24,
                                        ))
                                        .stroke(Stroke::new(UI_STROKE_WIDTH, colors.danger))
                                        .corner_radius(egui::CornerRadius::same(8))
                                        .inner_margin(Margin::symmetric(10, 7))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(error)
                                                    .size(14.0)
                                                    .color(colors.danger),
                                            );
                                        });
                                    ui.add_space(8.0);
                                }

                                self.ui_accounts_panel(ui);
                                ui.add_space(14.0);
                                self.ui_events_panel(ui);
                            });
                        });

                        ui.add_space(14.0);
                    });
            });
    }
}

impl eframe::App for RssAltsCheckerApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_zoom_controls(context);
        self.poll_background_scan();
        self.ui_app_bar(context);
        self.ui_main_content(context);
        self.ui_toast(context);

        if self.is_scanning || self.toast_deadline.is_some() {
            context.request_repaint_after(Duration::from_millis(16));
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::from(self.palette().background).to_array()
    }
}

fn parse_reason_suffix_usize(reason: &str, prefix: &str) -> Option<usize> {
    reason.strip_prefix(prefix)?.parse::<usize>().ok()
}

fn parse_trusted_reason(reason: &str) -> Option<(usize, usize)> {
    let prefix = "trusted-account-source:";
    let rest = reason.strip_prefix(prefix)?;
    let mut account_hits = None;
    let mut log_hits = None;

    for part in rest.split(';') {
        if let Some(value) = part.strip_prefix("log:") {
            log_hits = value.parse::<usize>().ok();
        } else if account_hits.is_none() {
            account_hits = part.parse::<usize>().ok();
        }
    }

    Some((account_hits?, log_hits.unwrap_or(0)))
}

fn setup_fonts(context: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        FONT_BODY.to_string(),
        FontData::from_static(include_bytes!("../assets/fonts/Roboto-var.ttf")).into(),
    );
    fonts.font_data.insert(
        FONT_HEADING.to_string(),
        FontData::from_static(include_bytes!("../assets/fonts/Roboto-var.ttf")).into(),
    );

    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, FONT_BODY.to_string());
    fonts
        .families
        .entry(FontFamily::Name(HEADING_FAMILY.into()))
        .or_default()
        .insert(0, FONT_HEADING.to_string());

    if let Some(bytes) = load_first_existing_font(&[
        r"C:\Windows\Fonts\CascadiaCode.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ]) {
        fonts
            .font_data
            .insert("mono_font".to_string(), FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "mono_font".to_string());
    }

    context.set_fonts(fonts);
}

fn dark_palette() -> UiPalette {
    UiPalette {
        background: Color32::from_rgb(30, 31, 34),
        topbar: Color32::from_rgb(35, 36, 40),
        surface: Color32::from_rgb(43, 45, 49),
        surface_alt: Color32::from_rgb(54, 57, 63),
        border: Color32::from_rgb(67, 70, 77),
        text: Color32::from_rgb(242, 243, 245),
        muted: Color32::from_rgb(174, 178, 185),
        accent: Color32::from_rgb(88, 101, 242),
        accent_hover: Color32::from_rgb(71, 82, 196),
        danger: Color32::from_rgb(240, 71, 71),
    }
}

fn light_palette() -> UiPalette {
    UiPalette {
        background: Color32::from_rgb(244, 246, 248),
        topbar: Color32::from_rgb(236, 240, 246),
        surface: Color32::from_rgb(255, 255, 255),
        surface_alt: Color32::from_rgb(248, 250, 252),
        border: Color32::from_rgb(223, 228, 235),
        text: Color32::from_rgb(23, 31, 42),
        muted: Color32::from_rgb(96, 111, 128),
        accent: Color32::from_rgb(45, 96, 235),
        accent_hover: Color32::from_rgb(31, 75, 197),
        danger: Color32::from_rgb(189, 47, 47),
    }
}

fn palette(is_dark_theme: bool) -> UiPalette {
    if is_dark_theme {
        dark_palette()
    } else {
        light_palette()
    }
}

fn apply_theme(context: &egui::Context, is_dark_theme: bool) {
    let mut style = (*context.style()).clone();
    let colors = palette(is_dark_theme);

    style.animation_time = 0.38;
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(13.0, 8.0);
    style.spacing.window_margin = Margin::same(14);
    style.spacing.indent = 14.0;

    style.visuals = if is_dark_theme {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    style.visuals.override_text_color = Some(colors.text);
    style.visuals.panel_fill = colors.background;
    style.visuals.window_fill = colors.surface;
    style.visuals.faint_bg_color = colors.surface;
    style.visuals.extreme_bg_color = colors.surface;
    style.visuals.collapsing_header_frame = true;

    style.visuals.window_corner_radius = egui::CornerRadius::same(8);
    style.visuals.menu_corner_radius = egui::CornerRadius::same(8);

    style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(7);
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(7);
    style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(7);
    style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(7);
    style.visuals.widgets.open.corner_radius = egui::CornerRadius::same(7);

    style.visuals.widgets.noninteractive.bg_fill = colors.surface_alt;
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.border);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.text);

    style.visuals.widgets.inactive.bg_fill = colors.surface;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.border);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.text);

    style.visuals.widgets.hovered.bg_fill = colors.surface_alt;
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.accent_hover);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.text);

    style.visuals.widgets.active.bg_fill = colors.accent;
    style.visuals.widgets.active.bg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.accent_hover);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);

    style.visuals.widgets.open.bg_fill = colors.surface_alt;
    style.visuals.widgets.open.bg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.accent_hover);
    style.visuals.widgets.open.fg_stroke = Stroke::new(UI_STROKE_WIDTH, colors.text);

    style.visuals.selection.bg_fill = colors.accent;
    style.visuals.selection.stroke = Stroke::new(UI_STROKE_WIDTH, colors.accent_hover);

    context.set_style(style);
}

fn event_line_color(line: &str, colors: UiPalette) -> Color32 {
    let text = line.to_ascii_lowercase();
    if text.contains("[deleted]") || text.contains("удалено:") {
        return colors.danger;
    }
    if text.contains("[renamed]") || text.contains("переименовано:") {
        return Color32::from_rgb(230, 197, 92);
    }
    if text.contains("[overwrite]")
        || text.contains("[extend]")
        || text.contains("изменено:")
        || text.contains("stream_change")
    {
        return Color32::from_rgb(138, 186, 255);
    }
    if text.contains("warning:") || text.contains("предупреж") {
        return Color32::from_rgb(241, 171, 89);
    }
    if text.contains("ошибка") || text.contains("failed") {
        return colors.danger;
    }
    if text.contains("сканирование завершено") || text.contains("готово:")
    {
        return Color32::from_rgb(127, 210, 144);
    }
    colors.muted
}

fn load_first_existing_font(candidates: &[&str]) -> Option<Vec<u8>> {
    for path in candidates {
        if let Ok(bytes) = fs::read(path) {
            return Some(bytes);
        }
    }
    None
}

fn load_icon_data() -> Option<egui::IconData> {
    let bytes = include_bytes!("../rss.ico");
    let icon = image::load_from_memory_with_format(bytes, image::ImageFormat::Ico)
        .ok()?
        .into_rgba8();
    let (width, height) = icon.dimensions();
    Some(egui::IconData {
        rgba: icon.into_raw(),
        width,
        height,
    })
}
