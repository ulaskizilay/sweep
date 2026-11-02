//! One question, asked the same way by every command that changes something.
//!
//! Two properties matter more than the wording:
//!
//! * **A pipe is never a yes.** Reading the answer from stdin means a cron job
//!   or a shell loop can answer a prompt with its own input, so a run whose
//!   stdin is not a terminal is declined before the question is printed. `--yes`
//!   is the only way to say yes without a person.
//! * **A decline is a statement, not silence.** The caller gets text that says
//!   nothing happened and what to run instead, and it exits with a code of its
//!   own, so "it did nothing" can never be mistaken for "it worked".
//!
//! The prompt goes to stderr and the answer comes from stdin, so `sweep clean
//! --dry-run > plan.txt` still shows the question on the terminal.

use std::io::{self, IsTerminal, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consent {
    Granted,
    /// Refusal text, phrased so the user knows nothing happened and what to do.
    Declined(String),
}

/// Asks `prompt` unless `yes` was given.
///
/// `what` completes the sentence "refusing to ___ without confirmation" and is
/// what the user reads when there is nobody to ask.
pub fn ask(prompt: &str, what: &str, yes: bool) -> Consent {
    if yes {
        return Consent::Granted;
    }
    if !io::stdin().is_terminal() {
        return Consent::Declined(format!(
            "refusing to {what} without confirmation: stdin is not a terminal. \
             Re-run with --yes if that is what you meant; nothing was changed."
        ));
    }

    eprint!("{prompt} [y/N] ");
    let _ = io::stderr().flush();

    let mut answer = String::new();
    match io::stdin().read_line(&mut answer) {
        // EOF on a terminal: the user closed the prompt, which is a no.
        Ok(0) => Consent::Declined("no answer on stdin; nothing was changed".to_string()),
        Ok(_) => match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Consent::Granted,
            _ => Consent::Declined(
                "cancelled; nothing was changed. Re-run with --dry-run to review the plan first."
                    .to_string(),
            ),
        },
        Err(error) => Consent::Declined(format!(
            "could not read the answer ({error}); nothing was changed"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_is_a_consent_without_a_terminal() {
        assert_eq!(ask("Continue?", "remove 3 items", true), Consent::Granted);
    }

    #[test]
    fn a_pipe_is_declined_even_when_it_holds_a_yes() {
        // The test process itself runs without a terminal on stdin, which is
        // exactly the case this refusal exists for.
        match ask("Continue?", "remove 3 items", false) {
            Consent::Declined(text) => {
                assert!(text.contains("nothing was changed"), "{text}");
                assert!(
                    text.contains("--yes"),
                    "the refusal names the way forward: {text}"
                );
            }
            Consent::Granted => panic!("a pipe must never answer a prompt"),
        }
    }
}
