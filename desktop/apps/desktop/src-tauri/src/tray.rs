//! The tray icon: builds the native menu from `agentnest_shell_api::tray::TrayModel`, swaps the icon, blinks the
//! yellow one and turns menu clicks into `TrayAction`s. The decisions (which entries exist, which clicks mean what) are
//! in the shell-api crate and unit tested there; this file only maps them onto Tauri types.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnest_protocol::Decision;
use agentnest_shell_api::tray::{
    parse_menu_id, ApprovalClick, TrayAction, TrayIcon, TrayItem, TrayModel,
};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_autostart::ManagerExt as AutostartExt;
use tauri_plugin_opener::OpenerExt;

use crate::state::Shell;

const ICON_GRAY: &[u8] = include_bytes!("../icons/tray-gray.png");
const ICON_BLUE: &[u8] = include_bytes!("../icons/tray-blue.png");
const ICON_YELLOW: &[u8] = include_bytes!("../icons/tray-yellow.png");
const ICON_RED: &[u8] = include_bytes!("../icons/tray-red.png");
const TRAY_ID: &str = "main-tray";
const BLINK_PERIOD: Duration = Duration::from_millis(700);

fn icon_bytes(icon: TrayIcon) -> &'static [u8] {
    match icon {
        TrayIcon::Gray => ICON_GRAY,
        TrayIcon::Blue => ICON_BLUE,
        TrayIcon::Yellow => ICON_YELLOW,
        TrayIcon::Red => ICON_RED,
    }
}

fn load_icon(icon: TrayIcon) -> Option<Image<'static>> {
    Image::from_bytes(icon_bytes(icon)).ok()
}

/// Shows and focuses the main window (tray click, "열기", single-instance callback, SAS modal).
pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn build_item(app: &AppHandle, item: &TrayItem) -> tauri::Result<Box<dyn IsMenuItem<Wry>>> {
    Ok(match item {
        TrayItem::Action { id, label } => Box::new(MenuItem::with_id(
            app,
            id.as_str(),
            label,
            true,
            None::<&str>,
        )?),
        TrayItem::Check { id, label, checked } => Box::new(CheckMenuItem::with_id(
            app,
            id.as_str(),
            label,
            true,
            *checked,
            None::<&str>,
        )?),
        // disabled text lines get an id of their own (menu ids should be unique)
        TrayItem::Info { label } => Box::new(MenuItem::with_id(
            app,
            format!("info:{label}"),
            label,
            false,
            None::<&str>,
        )?),
        TrayItem::Separator => Box::new(PredefinedMenuItem::separator(app)?),
        TrayItem::Submenu { label, items } => {
            let built = items
                .iter()
                .map(|i| build_item(app, i))
                .collect::<tauri::Result<Vec<_>>>()?;
            let refs: Vec<&dyn IsMenuItem<Wry>> = built.iter().map(|b| b.as_ref()).collect();
            Box::new(Submenu::with_items(app, label, true, &refs)?)
        }
    })
}

fn build_menu(app: &AppHandle, items: &[TrayItem]) -> tauri::Result<Menu<Wry>> {
    let built = items
        .iter()
        .map(|i| build_item(app, i))
        .collect::<tauri::Result<Vec<_>>>()?;
    let refs: Vec<&dyn IsMenuItem<Wry>> = built.iter().map(|b| b.as_ref()).collect();
    Menu::with_items(app, &refs)
}

/// Owns the tray icon and the last model applied to it.
pub struct TrayController {
    tray: tauri::tray::TrayIcon,
    last: Mutex<Option<TrayModel>>,
    blinking: Arc<AtomicBool>,
}

impl TrayController {
    /// Creates the tray icon (must run on the main thread: call it from `setup`).
    pub fn create(app: &AppHandle, model: &TrayModel) -> tauri::Result<Arc<Self>> {
        let menu = build_menu(app, &model.items)?;
        let mut builder = TrayIconBuilder::with_id(TRAY_ID)
            .menu(&menu)
            .tooltip(&model.tooltip)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| handle_menu_id(app, event.id().as_ref()))
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main(tray.app_handle());
                }
            });
        if let Some(icon) = load_icon(model.icon) {
            builder = builder.icon(icon);
        }
        let tray = builder.build(app)?;
        let blinking = Arc::new(AtomicBool::new(model.blink));
        let controller = Arc::new(Self {
            tray,
            last: Mutex::new(Some(model.clone())),
            blinking,
        });
        controller.spawn_blinker();
        Ok(controller)
    }

    fn spawn_blinker(self: &Arc<Self>) {
        let tray = self.tray.clone();
        let blinking = self.blinking.clone();
        tauri::async_runtime::spawn(async move {
            let mut on = false;
            loop {
                tokio::time::sleep(BLINK_PERIOD).await;
                if blinking.load(Ordering::Relaxed) {
                    on = !on;
                    let _ = tray.set_icon(load_icon(if on {
                        TrayIcon::Yellow
                    } else {
                        TrayIcon::Gray
                    }));
                }
            }
        });
    }

    /// Forgets the last applied model so the next [`apply`](Self::apply) rebuilds the native menu even if the model is
    /// unchanged. A click on a check item flips its native check mark; after a failed action the model is still the old
    /// one, so without this the menu would keep showing the wrong state.
    pub fn invalidate(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Applies a new model (main thread). Identical models are skipped.
    pub fn apply(&self, app: &AppHandle, model: TrayModel) {
        {
            let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
            if last.as_ref() == Some(&model) {
                return;
            }
            *last = Some(model.clone());
        }
        self.blinking.store(model.blink, Ordering::Relaxed);
        let _ = self.tray.set_icon(load_icon(model.icon));
        let _ = self.tray.set_tooltip(Some(&model.tooltip));
        if let Ok(menu) = build_menu(app, &model.items) {
            let _ = self.tray.set_menu(Some(menu));
        }
    }
}

/// Reacts to a clicked menu entry.
fn handle_menu_id(app: &AppHandle, id: &str) {
    let Some(action) = parse_menu_id(id) else {
        return;
    };
    match action {
        TrayAction::Open | TrayAction::Pair => show_main(app),
        TrayAction::Quit => app.exit(0),
        TrayAction::Restart => app.restart(),
        TrayAction::OpenLogs => {
            if let Some(shell) = app.try_state::<Shell>() {
                let dir = shell.api.logs_dir();
                let _ = std::fs::create_dir_all(&dir);
                let _ = app.opener().reveal_item_in_dir(&dir);
            }
        }
        TrayAction::SetAutostart(enable) => {
            let manager = app.autolaunch();
            let _ = if enable {
                manager.enable()
            } else {
                manager.disable()
            };
            invalidate_and_refresh(app);
        }
        TrayAction::SetPaused(paused) => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(shell) = app.try_state::<Shell>() {
                    if shell.api.remote_approval_pause(paused).await.is_ok() {
                        // no daemon event for this one: tell the window ourselves
                        if let Some(envelope) = shell.api.link_envelope().await {
                            crate::sink::emit_envelope(&app, &envelope);
                        }
                    }
                }
                invalidate_and_refresh(&app);
            });
        }
        TrayAction::SetLinkEnabled(enabled) => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(shell) = app.try_state::<Shell>() {
                    // the daemon emits the `link` event itself
                    let _ = shell.api.link_set_enabled(enabled).await;
                }
                invalidate_and_refresh(&app);
            });
        }
        TrayAction::Approval { request_id, kind } => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_approval(&app, &request_id, kind).await;
                crate::sink::refresh_tray(&app);
            });
        }
    }
}

/// After a click on a check item: force a rebuild of the native menu, then recompute it.
fn invalidate_and_refresh(app: &AppHandle) {
    if let Some(tray) = app.try_state::<Arc<TrayController>>() {
        tray.invalidate();
    }
    crate::sink::refresh_tray(app);
}

async fn handle_approval(app: &AppHandle, request_id: &str, kind: ApprovalClick) {
    let Some(shell) = app.try_state::<Shell>() else {
        return;
    };
    match kind {
        ApprovalClick::OpenWindow => show_main(app),
        ApprovalClick::Handoff => {
            let _ = shell.api.approval_handoff_local(request_id).await;
        }
        ApprovalClick::Allow | ApprovalClick::Deny => {
            let decision = if kind == ApprovalClick::Allow {
                Decision::Allow
            } else {
                Decision::Deny
            };
            // The shell re-checks the live card; anything that needs the long-press gate lands in the window.
            if shell.api.tray_decide(request_id, decision).await.is_err() {
                show_main(app);
            }
        }
    }
}
