//! System tray icon using StatusNotifier protocol via ksni.

use ksni::{menu::StandardItem, Icon, Tray, TrayService};

/// System tray handler for Sigil Auth.
pub struct SigilTray;

impl SigilTray {
    /// Spawn the tray service in a background thread.
    pub fn spawn() -> anyhow::Result<()> {
        std::thread::spawn(move || {
            let service = TrayService::new(SigilTray);
            let _ = service.run();
        });

        Ok(())
    }

    /// Activate the application via D-Bus.
    fn activate_app() {
        std::thread::spawn(|| {
            if let Err(e) = std::process::Command::new("dbus-send")
                .args(&[
                    "--session",
                    "--dest=org.sigilauth.Desktop",
                    "/org/sigilauth/Desktop",
                    "org.gtk.Actions.Activate",
                    "string:app.activate",
                    "array:",
                    "dict:string:variant:",
                ])
                .output()
            {
                tracing::error!(error = %e, "Failed to activate app via D-Bus");
            }
        });
    }
}

impl Tray for SigilTray {
    fn id(&self) -> String {
        "org.sigilauth.Desktop".to_string()
    }

    fn title(&self) -> String {
        "Sigil Auth".to_string()
    }

    fn icon_name(&self) -> String {
        "dialog-password".to_string()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        // Use icon theme by default, fallback handled by icon_name
        vec![]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        // Click on tray icon: show/focus the main window
        Self::activate_app();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;

        vec![
            StandardItem {
                label: "Servers".into(),
                activate: Box::new(|_this: &mut Self| {
                    Self::activate_app();
                }),
                icon_name: "network-server-symbolic".into(),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Show Sigil Auth".into(),
                activate: Box::new(|_this: &mut Self| {
                    Self::activate_app();
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|_this: &mut Self| {
                    std::process::exit(0);
                }),
                icon_name: "application-exit".into(),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![],
            title: "Sigil Auth".into(),
            description: "Secure authentication with hardware-backed keys".into(),
        }
    }
}
