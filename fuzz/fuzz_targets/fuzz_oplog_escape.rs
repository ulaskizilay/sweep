//! Fuzz target: the operation log must never be forgeable.
//!
//! Two ways a log can lie:
//!
//! * a path containing a newline splits one record into two, so the second half
//!   looks like an action nobody performed;
//! * a raw control byte reaches the file, so `grep`-based auditing and terminal
//!   review see something different from what is stored.
//!
//! The target asserts on the serialized bytes: exactly one record per call, no
//! byte below `0x20` (other than the terminating newline), and no `0x7f`.

#![no_main]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use libfuzzer_sys::fuzz_target;
use sweep_core::oplog::encode_path;
use sweep_core::{oplog, Action, Record};

fuzz_target!(|data: &[u8]| {
    let path = Path::new(OsStr::from_bytes(data));
    let (text, hex) = encode_path(path);

    let record = Record {
        ts: oplog::rfc3339(0),
        cmd: "clean",
        session: "fuzz",
        action: Action::Skipped,
        rule: "fuzz.rule",
        path: text,
        path_hex: hex,
        bytes: 0,
        reason: Some("probe_unknown"),
        detail: None,
    };

    let line = oplog::serialize(&record).expect("serialization cannot fail");

    assert_eq!(
        line.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "a record must occupy exactly one line"
    );
    assert_eq!(*line.last().expect("non-empty"), b'\n');

    let body = &line[..line.len() - 1];
    assert!(
        !body.iter().any(|byte| *byte < 0x20),
        "record carries a raw C0 control byte"
    );
    assert!(
        !body.contains(&0x7f),
        "record carries a raw DEL byte"
    );

    // Fidelity: a non-UTF-8 path must still be recoverable from the record.
    if let Some(hex) = record.path_hex.as_deref() {
        let recovered: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex pair"))
            .collect();
        assert_eq!(
            recovered,
            data,
            "path_hex must round-trip the exact path bytes"
        );
    }
});
