use super::PortmasterExt;
#[cfg(not(target_os = "linux"))]
use crate::portapi::client::connect;
#[cfg(target_os = "linux")]
use crate::portapi::client::connect_unix;
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter, Runtime};
use tokio::time::{sleep, Duration};

static WEBSOCKET_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signals the websocket thread to stop reconnecting and shut down gracefully.
pub fn shutdown_websocket() {
    WEBSOCKET_SHUTDOWN.store(true, Ordering::Release);
}

/// Starts a backround thread (via tauri::async_runtime) that connects to the Portmaster
/// Websocket database API.
pub fn start_websocket_thread<R: Runtime>(app: AppHandle<R>) {
    let app = app.clone();

    tauri::async_runtime::spawn(async move {
        loop {
            // Check if we should shutdown before attempting to connect
            if WEBSOCKET_SHUTDOWN.load(Ordering::Acquire) {
                debug!("WebSocket thread shutting down gracefully");
                break;
            }

            debug!("Trying to connect to websocket endpoint");

            #[cfg(target_os = "linux")]
            let api = connect_unix(
                super::API_SOCKET_PATH,
                &format!("ws://{}/api/database/v1", super::api_address()),
            )
            .await;
            #[cfg(not(target_os = "linux"))]
            let api = connect(&format!("ws://{}/api/database/v1", super::api_address())).await;

            match api {
                Ok(cli) => {
                    let portmaster = app.portmaster();

                    info!("Successfully connected to filemaster");

                    portmaster.on_connect(cli.clone());

                    // Monitor connection status
                    loop {
                        if WEBSOCKET_SHUTDOWN.load(Ordering::Acquire) {
                            debug!("Shutdown signal received, closing connection");
                            break;
                        }

                        if cli.is_closed() {
                            warn!("Connection to filemaster lost");
                            break;
                        }

                        sleep(Duration::from_secs(1)).await;
                    }

                    portmaster.on_disconnect();

                    // If shutdown was requested, exit the loop
                    if WEBSOCKET_SHUTDOWN.load(Ordering::Acquire) {
                        debug!("Exiting websocket thread after disconnect");
                        break;
                    }

                    warn!("lost connection to filemaster, retrying ....")
                }
                Err(err) => {
                    error!("failed to create portapi client: {}", err);

                    // A 403 means the daemon is up and reachable but refused the
                    // connection at the API authenticator (unauthorized client
                    // binary), which is a different failure than the service being
                    // down. Signal the splash so it can say "blocked" instead of
                    // "not running". Re-emitted on every retry, so the splash still
                    // catches it if it loads after the first attempt.
                    if err.to_string().contains("403") {
                        let _ = app.emit("connection-blocked", ());
                    }

                    app.portmaster().on_disconnect();

                    // Check shutdown flag before sleeping
                    if WEBSOCKET_SHUTDOWN.load(Ordering::Acquire) {
                        debug!("Shutdown requested, not retrying connection");
                        break;
                    }

                    // Sleep and retry with constant 2 second delay
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }

        info!("WebSocket thread terminated");
    });
}
