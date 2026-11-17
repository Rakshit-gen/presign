mod dataset;
mod net;
mod rebuild;
mod score;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: presign-eval build [--out DIR] [--rpc URL] [--archive-rpc URL] [--drainers N]
                          [--per-drainer N] [--blocks N] [--benign-per-block N] [--seed S]
       presign-eval score [--data DIR]

build  downloads ScamSniffer's blacklist, samples drainer activity through
       Blockscout and benign activity from recent blocks, and writes
       DIR/dataset.jsonl and DIR/manifest.json (default DIR: eval/data)
score  runs presign over the dataset and writes DIR/results.json plus a
       Markdown summary on stdout";

struct Args(Vec<String>);

impl Args {
    fn get(&self, flag: &str) -> Option<&str> {
        self.0
            .iter()
            .position(|a| a == flag)
            .and_then(|i| self.0.get(i + 1))
            .map(String::as_str)
    }

    fn num<T: std::str::FromStr>(&self, flag: &str, default: T) -> Result<T, String> {
        self.get(flag).map_or(Ok(default), |v| {
            v.parse().map_err(|_| format!("{flag} needs a number"))
        })
    }
}

fn run() -> Result<(), String> {
    let mut argv = std::env::args().skip(1);
    let cmd = argv.next().unwrap_or_default();
    let args = Args(argv.collect());
    match cmd.as_str() {
        "build" => {
            let opt = dataset::Options {
                rpc: args
                    .get("--rpc")
                    .unwrap_or("https://ethereum-rpc.publicnode.com")
                    .to_string(),
                archive_rpc: args
                    .get("--archive-rpc")
                    .unwrap_or("https://rpc.mevblocker.io")
                    .to_string(),
                drainers: args.num("--drainers", 200)?,
                per_drainer: args.num("--per-drainer", 5)?,
                blocks: args.num("--blocks", 300)?,
                benign_per_block: args.num("--benign-per-block", 3)?,
                seed: args.get("--seed").unwrap_or("presign-eval-1").to_string(),
            };
            dataset::build(
                &PathBuf::from(args.get("--out").unwrap_or("eval/data")),
                &opt,
            )
        }
        "score" => {
            let dir = PathBuf::from(args.get("--data").unwrap_or("eval/data"));
            let samples = score::load(&dir)?;
            let results = score::score(&samples, presign::analyze);
            let pretty = serde_json::to_string_pretty(&results).map_err(|e| e.to_string())?;
            std::fs::write(dir.join("results.json"), pretty).map_err(|e| e.to_string())?;
            print!("{}", score::markdown(&results));
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
