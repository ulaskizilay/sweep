//! Stable-toolchain equivalents of the fuzz targets.
//!
//! `cargo fuzz` needs nightly, so the properties it checks would otherwise only
//! run on the scheduled job. These tests run the same assertions over a
//! deterministic corpus on every `cargo test`, which is what actually protects a
//! pull request. The fuzz targets exist to explore *more* input, not to be the
//! only gate.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sweep_core::paths::is_within;
use sweep_core::{oplog, Action, AllowedRoot, Policy, Record, ValidateCtx, Verdict, Xdg};
use sweep_testkit::{PermissiveProbe, SAMPLE_MOUNTS};

/// xorshift64*, so the corpus is identical on every machine and every run.
/// A fuzz corpus that changes between CI runs cannot be bisected.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn xdg() -> Xdg {
    Xdg::resolve(|key| match key {
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .expect("home")
}

/// Paths that exercise the interesting shapes plus raw noise.
fn corpus(count: usize) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = vec![
        b"/".to_vec(),
        b"".to_vec(),
        b"relative".to_vec(),
        b"/home/u/.cache".to_vec(),
        b"/home/u/.ssh/id_ed25519".to_vec(),
        b"/usr/lib/firmware".to_vec(),
        b"/home/u/.cache/../../../etc/passwd".to_vec(),
        b"/home/u/.cache/a\0b".to_vec(),
        b"/home/u/.cache/line\nbreak".to_vec(),
        b"/home/u/.cache/..hidden".to_vec(),
        b"/mnt/usb/x".to_vec(),
        b"/var/cache/pacman/pkg/a.pkg.tar.zst".to_vec(),
        // Invalid UTF-8 in the leaf and in a directory component.
        vec![b'/', b'h', b'o', b'm', b'e', b'/', 0xff, 0xfe],
        vec![0x80, 0x81],
    ];

    let mut rng = Rng::new(0x5eed_1234_abcd_0001);
    while seeds.len() < count {
        let length = rng.below(48);
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rng.byte());
        }
        // Half the generated inputs get a valid absolute prefix so they reach
        // past the lexical checks instead of only exercising `not_absolute`.
        if rng.below(2) == 0 {
            let mut prefixed = b"/home/u/.cache/".to_vec();
            prefixed.extend_from_slice(&bytes);
            seeds.push(prefixed);
        } else {
            seeds.push(bytes);
        }
    }
    seeds
}

#[test]
fn arbitrary_paths_never_panic_and_never_escape_a_rule_root() {
    let xdg = xdg();
    // Permissive on purpose: `FakeProbe` only knows the paths it was told about,
    // so a generated child would stop at `not_found` and the allow path would
    // never be exercised. Mount facts and protected roots still apply.
    let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
    let allowed = vec![
        AllowedRoot::new("/home/u/.cache"),
        AllowedRoot::new("/tmp"),
        AllowedRoot::new("/var/cache/pacman"),
    ];
    let ctx = ValidateCtx {
        xdg: &xdg,
        probe: &probe,
        allowed: &allowed,
        policy: Policy::default(),
    };

    let mut allowed_count = 0usize;
    for bytes in corpus(20_000) {
        let path = PathBuf::from(OsStr::from_bytes(&bytes));
        match sweep_core::validate(&path, &ctx) {
            Verdict::Allow { physical } => {
                allowed_count += 1;
                assert!(
                    allowed.iter().any(|root| is_within(&root.path, &physical)),
                    "allowed a path outside every rule root: {:?}",
                    physical
                );
                assert_ne!(physical, Path::new("/"), "allowed the filesystem root");
            }
            Verdict::Deny(reason) => {
                assert!(
                    !reason.code().is_empty(),
                    "refusal without a stable reason code for {:?}",
                    path
                );
            }
        }
    }
    // If nothing was ever allowed, the test stopped proving anything about the
    // allow path and would not notice a regression there.
    assert!(
        allowed_count > 0,
        "the corpus never produced an allowed path; the probe fixture is too strict"
    );
}

#[test]
fn every_byte_value_stays_on_one_escaped_log_line() {
    // Exhaustive over a single byte, which is the whole C0/DEL space that can
    // break the line format.
    for byte in 0u8..=0xff {
        let mut bytes = b"/home/u/.cache/".to_vec();
        bytes.push(byte);
        bytes.extend_from_slice(b"tail");
        assert_record_is_safe(&bytes, byte);
    }

    // And over generated multi-byte inputs, so escaping cannot be defeated by a
    // combination rather than a single byte.
    let mut rng = Rng::new(0xdead_beef_0000_0002);
    for _ in 0..5_000 {
        let length = rng.below(40);
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(rng.byte());
        }
        assert_record_is_safe(&bytes, 0);
    }
}

fn assert_record_is_safe(bytes: &[u8], context: u8) {
    let path = Path::new(OsStr::from_bytes(bytes));
    let (text, hex) = oplog::encode_path(path);
    let record = Record {
        ts: oplog::rfc3339(0),
        cmd: "clean",
        session: "corpus",
        action: Action::Skipped,
        rule: "corpus.rule",
        path: text,
        path_hex: hex.clone(),
        bytes: 0,
        reason: Some("control_byte"),
        detail: None,
    };

    let line = oplog::serialize(&record).expect("serialization cannot fail");
    assert_eq!(
        line.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "byte {context:#04x}: a record must occupy exactly one line"
    );

    let body = &line[..line.len() - 1];
    assert!(
        !body.iter().any(|byte| *byte < 0x20),
        "byte {context:#04x}: record carries a raw C0 byte"
    );
    assert!(
        !body.contains(&0x7f),
        "byte {context:#04x}: record carries a raw DEL byte"
    );

    // Non-UTF-8 paths must remain recoverable: losing the exact name in the
    // audit trail is worse than an extra field.
    if !std::str::from_utf8(bytes).is_ok() {
        let hex = hex.expect("non-UTF-8 path must carry path_hex");
        let recovered: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex pair"))
            .collect();
        assert_eq!(recovered, bytes, "path_hex must round-trip exact bytes");
    }
}
