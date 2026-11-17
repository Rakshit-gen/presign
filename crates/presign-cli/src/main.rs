use presign::{Severity, analyze};
use std::{env, fs, io::Read, process::ExitCode};

const USAGE: &str = "\
usage: presign [--json] [FILE]
       presign --version

Reads an EIP-1193 request ({\"method\": ..., \"params\": [...]}) from FILE or
stdin and reports what signing it would do.

exit codes: 0 safe to review, 1 high or critical risk, 2 bad input";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("presign {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let json_out = args.iter().any(|a| a == "--json");
    if let Some(bad) = args.iter().find(|a| a.starts_with('-') && *a != "--json") {
        eprintln!("presign: unknown flag {bad}\n\n{USAGE}");
        return ExitCode::from(2);
    }
    let path = args.iter().find(|a| !a.starts_with('-'));

    let input = match path {
        Some(p) => fs::read_to_string(p).map_err(|e| format!("{p}: {e}")),
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map(|_| s)
                .map_err(|e| e.to_string())
        }
    };
    let report = input
        .and_then(|s| serde_json::from_str(&s).map_err(|e| format!("invalid JSON: {e}")))
        .and_then(|req| analyze(&req));
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            eprintln!("presign: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

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
    if report.verdict() >= Severity::High {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
