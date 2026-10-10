use proofgate::analyze::{self, CheckReport, DiffReport, Direction, RuleStatus};
use proofgate::model::{Effect, InvariantKind, Policy};
use std::collections::BTreeMap;
use std::process::ExitCode;

const USAGE: &str = "proofgate: exact semantic diff and invariant proofs for access policies

usage:
  proofgate check <policy.json> [--json]
  proofgate diff <old.json> <new.json> [--json] [--fail-on-widen]
  proofgate eval <policy.json> <dimension=value>...
  proofgate vectors <policy.json>

exit codes: 0 ok, 1 invariant failed or access widened, 2 bad input";

fn load(path: &str) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    Policy::parse(&text).map_err(|e| format!("{path}: {e}"))
}

fn fmt_when(when: &BTreeMap<String, Vec<String>>) -> String {
    if when.is_empty() {
        return "any request".into();
    }
    when.iter()
        .map(|(k, v)| format!("{k}={}", v.join("|")))
        .collect::<Vec<_>>()
        .join("  ")
}

fn print_check(r: &CheckReport) {
    println!("{}  {}", r.name, &r.digest[..12]);
    println!(
        "{} requests: {} allowed, {} denied\n",
        r.space, r.allowed, r.denied
    );
    for rule in &r.rules {
        let effect = if rule.effect == Effect::Allow {
            "allow"
        } else {
            "deny "
        };
        let note = match rule.status {
            RuleStatus::Active => String::new(),
            RuleStatus::Dead => "  DEAD: an earlier rule decides everything this matches".into(),
            RuleStatus::Redundant => "  REDUNDANT: removing it changes no decision".into(),
        };
        println!("  {effect}  {:<28} decides {}{note}", rule.id, rule.decides);
    }
    println!();
    for inv in &r.invariants {
        let kind = if inv.kind == InvariantKind::NeverAllow {
            "never allow"
        } else {
            "always allow"
        };
        if inv.holds {
            println!("  PROVEN   {kind}: {}", inv.description);
        } else {
            println!("  FAILS    {kind}: {}", inv.description);
            for c in inv.counterexamples.iter().take(5) {
                println!(
                    "             {} requests, {}, decided by {}",
                    c.requests,
                    fmt_when(&c.when),
                    c.decided_by
                );
            }
        }
    }
}

fn print_diff(r: &DiffReport) {
    println!("{} -> {}", &r.from_digest[..12], &r.to_digest[..12]);
    if r.changes.is_empty() {
        println!("no decision changes");
        return;
    }
    println!(
        "{} newly allowed, {} newly denied  (fingerprint {})\n",
        r.newly_allowed,
        r.newly_denied,
        &r.fingerprint[..12]
    );
    for c in &r.changes {
        let tag = if c.direction == Direction::NewlyAllowed {
            "NEWLY ALLOWED"
        } else {
            "newly denied "
        };
        println!(
            "  {tag}  {} request{}  {}",
            c.requests,
            if c.requests == 1 { "" } else { "s" },
            fmt_when(&c.when)
        );
        println!(
            "                 was {}, now {}",
            c.was_decided_by, c.now_decided_by
        );
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let json = args.iter().any(|a| a == "--json");
    let widen = args.iter().any(|a| a == "--fail-on-widen");
    let pos: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with("--"))
        .collect();
    match (args.first().map(String::as_str), pos.as_slice()) {
        (Some("check"), [p]) => {
            let r = analyze::check(&load(p)?);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?
                );
            } else {
                print_check(&r);
            }
            Ok(if r.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        (Some("diff"), [a, b]) => {
            let r = analyze::diff(&load(a)?, &load(b)?).map_err(|e| e.to_string())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?
                );
            } else {
                print_diff(&r);
            }
            Ok(if widen && r.newly_allowed > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        (Some("eval"), [p, rest @ ..]) => {
            let request = rest
                .iter()
                .map(|kv| {
                    kv.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .ok_or(format!("expected key=value, got '{kv}'"))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?;
            let d = analyze::eval(&load(p)?, &request).map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string(&d).map_err(|e| e.to_string())?);
            Ok(ExitCode::SUCCESS)
        }
        (Some("vectors"), [p]) => {
            for v in analyze::vectors(&load(p)?, 2_000_000).map_err(|e| e.to_string())? {
                println!("{}", serde_json::to_string(&v).map_err(|e| e.to_string())?);
            }
            Ok(ExitCode::SUCCESS)
        }
        (Some("--version"), _) => {
            println!("proofgate {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    }
}
