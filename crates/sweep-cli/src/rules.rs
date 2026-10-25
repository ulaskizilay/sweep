//! `sweep rules` — what the catalog contains, and whether it still compiles.
//!
//! `list` is the review surface: every rule with its section, kind, retention
//! and resolved root, including the ones that are deliberately switched off.
//! `verify` is the gate: it compiles every pack exactly the way `clean` does and
//! fails with the same reasons, so a broken user overlay is one command away
//! from a diagnosis instead of a mysterious refusal during cleanup.

use std::process::ExitCode;

use serde::Serialize;
use sweep_core::rules::{builtin, Privilege, Requirement, Rule, RuleSet, Section};
use sweep_core::Xdg;

#[derive(Debug, Serialize)]
struct ListReport {
    packs: usize,
    rules: usize,
    enabled: usize,
    sections: Vec<SectionReport>,
    rule: Vec<RuleReport>,
}

#[derive(Debug, Serialize)]
struct SectionReport {
    section: &'static str,
    rules: usize,
    enabled: usize,
    /// True when `clean` skips the whole section unless it is named with `--only`.
    opt_in: bool,
}

#[derive(Debug, Serialize)]
struct RuleReport {
    id: String,
    section: &'static str,
    kind: &'static str,
    enabled: bool,
    keep_days: u32,
    recoverable: bool,
    privilege: &'static str,
    root: String,
    resolved_root: String,
    requires: Vec<RequirementReport>,
    exclude: Vec<String>,
    pattern: Vec<String>,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct RequirementReport {
    label: String,
    satisfied: bool,
}

pub fn list(json: bool, verbose: u8) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep rules: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    let set = match RuleSet::load(&xdg) {
        Ok(set) => set,
        Err(errors) => {
            report_errors(&errors);
            return ExitCode::from(crate::EXIT_INVALID_RULES);
        }
    };

    let report = build(&set, &xdg);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep rules: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", render(&report, verbose));
    }
    ExitCode::SUCCESS
}

pub fn verify(json: bool, verbose: u8) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep rules: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    match RuleSet::load(&xdg) {
        Ok(set) => {
            let report = build(&set, &xdg);
            if json {
                match serde_json::to_string_pretty(&VerifyReport {
                    ok: true,
                    packs: report.packs,
                    rules: report.rules,
                    enabled: report.enabled,
                    errors: Vec::new(),
                }) {
                    Ok(text) => println!("{text}"),
                    Err(error) => {
                        eprintln!("sweep rules: cannot serialise report: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "rules verify: {} packs, {} rules, {} enabled",
                    report.packs, report.rules, report.enabled
                );
                println!("  built-in packs and user overlay compile and are internally consistent");
                if verbose > 0 {
                    for section in &report.sections {
                        println!(
                            "  {:<18} {:>3} rules, {:>3} enabled",
                            section.section, section.rules, section.enabled
                        );
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(errors) => {
            if json {
                let payload = VerifyReport {
                    ok: false,
                    packs: builtin::BUILTIN_PACKS.len(),
                    rules: 0,
                    enabled: 0,
                    errors: errors
                        .iter()
                        .map(|error| ErrorReport {
                            code: error.kind.code(),
                            pack: error.pack.clone(),
                            rule: error.rule.clone(),
                            message: error.message.clone(),
                        })
                        .collect(),
                };
                // The document is still printed on stdout: a script reading
                // `--json` must not have to parse prose off stderr.
                let _ = serde_json::to_string_pretty(&payload).map(|text| println!("{text}"));
            } else {
                report_errors(&errors);
            }
            ExitCode::from(crate::EXIT_INVALID_RULES)
        }
    }
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    ok: bool,
    packs: usize,
    rules: usize,
    enabled: usize,
    errors: Vec<ErrorReport>,
}

#[derive(Debug, Serialize)]
struct ErrorReport {
    code: &'static str,
    pack: String,
    rule: Option<String>,
    message: String,
}

fn report_errors(errors: &[sweep_core::RuleError]) {
    eprintln!(
        "sweep rules: {} {} refused at load",
        errors.len(),
        if errors.len() == 1 { "rule" } else { "rules" }
    );
    for error in errors {
        match &error.rule {
            Some(rule) => eprintln!("  {rule}  [{}]", error.kind.code()),
            None => eprintln!("  {}  [{}]", error.pack, error.kind.code()),
        }
        eprintln!("    {}", error.message);
    }
    eprintln!(
        "  built-in packs are compiled into sweep; only ~/.config/sweep/rules.d/*.toml can be edited"
    );
}

fn build(set: &RuleSet, xdg: &Xdg) -> ListReport {
    let sections = set
        .sections()
        .into_iter()
        .map(|summary| SectionReport {
            section: summary.section.as_str(),
            rules: summary.rules,
            enabled: summary.enabled,
            opt_in: summary.section.is_opt_in(),
        })
        .collect();

    let mut rules: Vec<&Rule> = set.rules().iter().collect();
    // Section order first, then id: a reviewer reads the catalog the way `clean`
    // reports it, not the way the packs happen to be concatenated.
    rules.sort_by_key(|rule| {
        (
            Section::ALL
                .iter()
                .position(|section| *section == rule.section)
                .unwrap_or(usize::MAX),
            rule.id.clone(),
        )
    });

    let rule = rules
        .into_iter()
        .map(|rule| RuleReport {
            id: rule.id.to_string(),
            section: rule.section.as_str(),
            kind: rule.kind.as_str(),
            enabled: rule.enabled,
            keep_days: rule.keep_days,
            recoverable: rule.recoverable,
            privilege: rule.privilege.as_str(),
            root: rule.root.raw().to_string(),
            resolved_root: rule.expanded_root(xdg).display().to_string(),
            requires: rule
                .requires
                .iter()
                .map(|requirement: &Requirement| RequirementReport {
                    label: requirement.label(),
                    satisfied: requirement.satisfied(xdg),
                })
                .collect(),
            exclude: rule
                .exclude
                .iter()
                .map(|pattern| pattern.source().to_string())
                .collect(),
            pattern: rule
                .patterns
                .iter()
                .map(|pattern| pattern.source().to_string())
                .collect(),
            evidence: rule.evidence.clone(),
        })
        .collect::<Vec<_>>();

    ListReport {
        packs: builtin::BUILTIN_PACKS.len(),
        rules: set.len(),
        enabled: set.rules().iter().filter(|rule| rule.enabled).count(),
        sections,
        rule,
    }
}

fn render(report: &ListReport, verbose: u8) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "sweep rules — {} packs, {} rules, {} enabled\n\n",
        report.packs, report.rules, report.enabled
    ));

    out.push_str(&format!(
        "  {:<18} {:>5} {:>8}\n",
        "section", "rules", "enabled"
    ));
    for section in &report.sections {
        out.push_str(&format!(
            "  {:<18} {:>5} {:>8}{}\n",
            section.section,
            section.rules,
            section.enabled,
            if section.opt_in { "  opt-in" } else { "" }
        ));
    }
    let opt_in: Vec<&str> = report
        .sections
        .iter()
        .filter(|section| section.opt_in)
        .map(|section| section.section)
        .collect();
    if !opt_in.is_empty() {
        out.push_str(&format!(
            "\n  {} {} opt-in: `sweep clean` leaves it alone until you name it with `--only`.\n",
            opt_in.join(", "),
            if opt_in.len() == 1 { "is" } else { "are" }
        ));
    }

    let mut current = "";
    for rule in &report.rule {
        if rule.section != current {
            out.push_str(&format!("\n  {}\n", rule.section));
            current = rule.section;
        }
        let state = if !rule.enabled {
            "off"
        } else if rule.privilege == Privilege::Root.as_str() {
            "root"
        } else {
            "on"
        };
        let retention = if rule.keep_days == 0 {
            "now".to_string()
        } else {
            format!("{}d", rule.keep_days)
        };
        out.push_str(&format!(
            "    {:<34} {:<13} {:>4}  {:<4}  {}\n",
            rule.id, rule.kind, retention, state, rule.resolved_root
        ));
        if verbose > 0 {
            for requirement in &rule.requires {
                let mark = if requirement.satisfied {
                    "ok"
                } else {
                    "missing"
                };
                out.push_str(&format!(
                    "      requires {:<40} {mark}\n",
                    requirement.label
                ));
            }
            if !rule.exclude.is_empty() {
                out.push_str(&format!("      exclude  {}\n", rule.exclude.join(", ")));
            }
            if !rule.pattern.is_empty() {
                out.push_str(&format!("      pattern  {}\n", rule.pattern.join(", ")));
            }
            if !rule.evidence.is_empty() {
                out.push_str(&format!("      why      {}\n", rule.evidence));
            }
        }
    }

    out.push_str(
        "\n  on = runs, off = declared disabled, root = needs privilege (arrives in M4)\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/home/u".into()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn the_report_covers_every_rule_and_names_the_disabled_ones() {
        let set = RuleSet::load_builtin(&xdg()).expect("built-ins load");
        let report = build(&set, &xdg());
        assert_eq!(report.rules, set.len());
        assert!(report.sections.len() >= 10);
        assert!(report.rule.iter().any(|rule| !rule.enabled));
        assert!(report
            .rule
            .iter()
            .all(|rule| rule.resolved_root.starts_with('/')));
    }

    #[test]
    fn rendering_shows_a_disabled_rule_as_off() {
        let set = RuleSet::load_builtin(&xdg()).expect("built-ins load");
        let report = build(&set, &xdg());
        let text = render(&report, 0);
        assert!(text.contains("system.pacman.package-cache"), "{text}");
        assert!(text.contains(" off "), "{text}");
        let verbose = render(&report, 1);
        assert!(verbose.contains("why"), "{verbose}");
    }
}
