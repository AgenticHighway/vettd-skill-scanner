//! Localhost HTTP shim exposing `vettd-skill-scanner` to the scanner suite.
//!
//! Endpoints (`routes.rs`): `GET /health` and `POST /scan`. The listen port
//! comes from the `VETTD_SHIM_PORT` env var (default 8788), matching the
//! cisco shim's `CISCO_SHIM_PORT` precedent — port/bind settings belong to
//! the shim process; the suite's TOML config holds the URL its adapter dials.
//!
//! Like `parity-adapter`, this crate lives outside the scanner library to
//! preserve that crate's zero-I/O guarantee.

mod routes;

use std::net::SocketAddr;
use std::process::ExitCode;

/// Loopback only — the shim is a sidecar, never an externally reachable service.
const BIND_ADDR: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8788;
const PORT_ENV: &str = "VETTD_SHIM_PORT";

#[tokio::main]
async fn main() -> ExitCode {
    let port = match std::env::var(PORT_ENV) {
        Ok(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("http-shim: invalid {PORT_ENV} value: {raw:?}");
                return ExitCode::FAILURE;
            }
        },
        Err(_) => DEFAULT_PORT,
    };

    let addr: SocketAddr = match format!("{BIND_ADDR}:{port}").parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("http-shim: invalid bind address: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("http-shim: failed to bind {addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("http-shim: listening on http://{addr}");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    if let Err(e) = axum::serve(listener, routes::router())
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("http-shim: server error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
