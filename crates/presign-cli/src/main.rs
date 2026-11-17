use presign::online::{Rpc, enrich};
use presign::{Severity, analyze};
use std::{env, fs, io::Read, process::ExitCode, time::Duration};

const USAGE: &str = "\
usage: presign [--json] [--rpc URL] [FILE]
       presign --version

Reads an EIP-1193 request ({\"method\": ..., \"params\": [...]}) from FILE or
stdin and reports what signing it would do.

--rpc URL  also check approval spenders on-chain through this JSON-RPC
           endpoint (PRESIGN_RPC is used when the flag is absent)

exit codes: 0 safe to review, 1 high or critical risk, 2 bad input";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("presign: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut json_out = false;
    let mut rpc = env::var("PRESIGN_RPC").ok().filter(|s| !s.is_empty());
    let mut path = None;
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-V" | "--version" => {
                println!("presign {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "--json" => json_out = true,
            "--rpc" => rpc = Some(args.next().ok_or("--rpc needs a URL")?),
            f if f.starts_with('-') => return Err(format!("unknown flag {f}")),
            _ if path.is_some() => return Err("only one input file".into()),
            _ => path = Some(a),
        }
    }

    let input = match &path {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?,
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| e.to_string())?;
            s
        }
    };
    let req = serde_json::from_str(&input).map_err(|e| format!("invalid JSON: {e}"))?;
    let mut report = analyze(&req)?;
    if let Some(url) = rpc {
        enrich(&mut report, &mut Rpc::new(url, Duration::from_secs(10)));
    }

    if json_out {
        println!("{}", report.to_json());
    } else {
        println!("verdict: {}", report.verdict().to_string().to_uppercase());
        if let Some(h) = report.hashes {
            println!("signing hash: {}", h.signing);
            println!("domain hash:  {}", h.domain);
            println!("message hash: {}", h.message);
            println!("check these match your hardware wallet screen before approving");
        }
        for f in &report.findings {
            println!("  [{}] {}", f.severity, f.message);
        }
    }
    Ok(if report.verdict() >= Severity::High {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
