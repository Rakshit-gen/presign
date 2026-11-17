//! HTTP API for presign.
//!
//! `POST /v1/analyze` takes the same EIP-1193 request the CLI reads and
//! returns the report as JSON. `GET /healthz` is a liveness probe and
//! `GET /metrics` serves Prometheus text.
//!
//! Configuration comes from the environment:
//!
//! - `PRESIGN_ADDR`: listen address (default `0.0.0.0:8080`)
//! - `PRESIGN_RPC`: JSON-RPC endpoint for on-chain spender checks (off when unset)
//! - `PRESIGN_MAX_BODY`: request body limit in bytes (default 262144)
//! - `PRESIGN_RPC_TIMEOUT_MS`: per-request budget for chain lookups (default 3000)

mod metrics;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics::Metrics;
use presign::online::{Rpc, enrich};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct AppState {
    rpc: Option<Rpc>,
    rpc_budget: Duration,
    metrics: Metrics,
}

fn app(state: Arc<AppState>, max_body: usize) -> Router {
    Router::new()
        .route("/v1/analyze", post(analyze))
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"error": message.into()}))).into_response()
}

async fn analyze(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let started = Instant::now();
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            state.metrics.rejected();
            return error(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}"));
        }
    };
    let mut report = match presign::analyze(&req) {
        Ok(r) => r,
        Err(e) => {
            state.metrics.rejected();
            return error(StatusCode::UNPROCESSABLE_ENTITY, e);
        }
    };

    let mut online = "off";
    if let Some(rpc) = &state.rpc {
        let mut chain = rpc.clone();
        let offline = report.clone();
        let lookup = tokio::task::spawn_blocking(move || {
            enrich(&mut report, &mut chain);
            report
        });
        report = match tokio::time::timeout(state.rpc_budget, lookup).await {
            Ok(Ok(enriched)) => {
                online = "ok";
                enriched
            }
            _ => {
                online = "timeout";
                offline
            }
        };
    }

    let verdict = report.verdict();
    let mut body = report.to_json();
    body["online"] = json!(online);
    state.metrics.analyzed(verdict, started.elapsed());
    Json(body).into_response()
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("{name} must be a number, got {v}")),
        Err(_) => Ok(default),
    }
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let addr = std::env::var("PRESIGN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let max_body = env_num("PRESIGN_MAX_BODY", 256 * 1024)?;
    let rpc_budget = Duration::from_millis(env_num("PRESIGN_RPC_TIMEOUT_MS", 3000)?);
    let rpc = std::env::var("PRESIGN_RPC")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|url| Rpc::new(url, rpc_budget));
    let state = Arc::new(AppState {
        rpc,
        rpc_budget,
        metrics: Metrics::default(),
    });

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    eprintln!(
        "presign-server {} listening on {addr} (online checks {})",
        env!("CARGO_PKG_VERSION"),
        if state.rpc.is_some() { "on" } else { "off" }
    );
    axum::serve(listener, app(state, max_body))
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYBIT: &str = include_str!("../../presign/tests/fixtures/bybit_exec_transaction.json");

    async fn spawn(max_body: usize) -> String {
        let state = Arc::new(AppState {
            rpc: None,
            rpc_budget: Duration::from_secs(1),
            metrics: Metrics::default(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app(state, max_body)).await });
        format!("http://{addr}")
    }

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into()
    }

    fn post(url: &str, body: &str) -> (u16, Value) {
        let mut r = agent()
            .post(url)
            .content_type("application/json")
            .send(body)
            .unwrap();
        let status = r.status().as_u16();
        let text = r.body_mut().read_to_string().unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn analyze_returns_the_report() {
        let base = spawn(1 << 20).await;
        let (status, body) =
            tokio::task::spawn_blocking(move || post(&format!("{base}/v1/analyze"), BYBIT))
                .await
                .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["verdict"], "critical");
        assert_eq!(body["online"], "off");
        assert_eq!(body["findings"][0]["code"], "safe.delegatecall");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bad_requests_get_json_errors_and_are_counted() {
        let base = spawn(64).await;
        tokio::task::spawn_blocking(move || {
            let url = format!("{base}/v1/analyze");
            let (s, b) = post(&url, "{");
            assert_eq!(s, 400);
            assert!(b["error"].as_str().unwrap().starts_with("invalid JSON"));
            let (s, _) = post(&url, r#"{"method":"eth_foo","params":[]}"#);
            assert_eq!(s, 422);
            let (s, _) = post(&url, BYBIT);
            assert_eq!(s, 413);

            let mut m = agent().get(format!("{base}/metrics")).call().unwrap();
            let text = m.body_mut().read_to_string().unwrap();
            assert!(text.contains("presign_rejected_total 2"), "{text}");
            let mut h = agent().get(format!("{base}/healthz")).call().unwrap();
            assert_eq!(h.body_mut().read_to_string().unwrap(), "ok");
        })
        .await
        .unwrap();
    }
}
