//! Blocking HTTP with pacing and retries, for rate-limited public APIs.

use serde_json::{Value, json};
use std::thread::sleep;
use std::time::{Duration, Instant};

const USER_AGENT: &str = concat!("presign-eval/", env!("CARGO_PKG_VERSION"));
const ATTEMPTS: u32 = 6;

pub struct Http {
    agent: ureq::Agent,
    min_gap: Duration,
    last: Option<Instant>,
}

impl Http {
    /// `min_gap` is the minimum time between two requests from this client.
    pub fn new(min_gap: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            agent,
            min_gap,
            last: None,
        }
    }

    fn pace(&mut self) {
        if let Some(t) = self.last {
            let since = t.elapsed();
            if since < self.min_gap {
                sleep(self.min_gap - since);
            }
        }
        self.last = Some(Instant::now());
    }

    /// GET a JSON document. A 404 returns `Value::Null`.
    pub fn get_json(&mut self, url: &str) -> Result<Value, String> {
        self.with_retries(url, |agent| {
            agent.get(url).header("user-agent", USER_AGENT).call()
        })
    }

    /// Call a JSON-RPC method and return its `result`.
    pub fn rpc(&mut self, url: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let reply = self.with_retries(url, |agent| {
            agent
                .post(url)
                .header("user-agent", USER_AGENT)
                .send_json(&body)
        })?;
        if let Some(err) = reply.get("error") {
            return Err(format!("{method}: {err}"));
        }
        Ok(reply["result"].clone())
    }

    fn with_retries(
        &mut self,
        url: &str,
        send: impl Fn(&ureq::Agent) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<Value, String> {
        let mut last_err = String::new();
        for attempt in 0..ATTEMPTS {
            self.pace();
            match send(&self.agent) {
                Ok(mut resp) => match resp.status().as_u16() {
                    200 => return resp.body_mut().read_json().map_err(|e| e.to_string()),
                    404 => return Ok(Value::Null),
                    s @ (429 | 500..=599) => last_err = format!("HTTP {s}"),
                    s => return Err(format!("{url}: HTTP {s}")),
                },
                Err(e) => last_err = e.to_string(),
            }
            sleep(Duration::from_secs(1 << attempt));
        }
        Err(format!("{url}: {last_err} after {ATTEMPTS} attempts"))
    }
}
