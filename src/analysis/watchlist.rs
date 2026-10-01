//! Keyword/regex watchlist for path segments.
//!
//! File format (one rule per line, `#` starts a comment):
//!
//! ```text
//! high: mimikatz              # substring, case-insensitive
//! medium: re:^psexe(c|svc)    # regular expression (case-insensitive)
//! low: dump | Credential dumping output folder
//! ```
//!
//! An optional `| label` suffix sets the description shown in findings.

use super::findings::Severity;
use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
pub enum Matcher {
    Substring(String),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct WatchRule {
    pub severity: Severity,
    pub matcher: Matcher,
    pub pattern: String,
    pub label: String,
}

impl WatchRule {
    pub fn matches(&self, segment: &str) -> bool {
        match &self.matcher {
            Matcher::Substring(s) => segment.to_lowercase().contains(s.as_str()),
            Matcher::Regex(r) => r.is_match(segment),
        }
    }
}

/// Parses watchlist text. Invalid lines are reported, not fatal.
pub fn parse(text: &str) -> (Vec<WatchRule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = match line.find(" #") {
            Some(p) => &line[..p],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (sev, rest) = match line.split_once(':') {
            Some((s, r)) if Severity::parse(s.trim()).is_some() => {
                (Severity::parse(s.trim()).unwrap(), r.trim())
            }
            _ => (Severity::Low, line),
        };
        let (pat, label) = match rest.split_once(" | ") {
            Some((p, l)) => (p.trim(), l.trim().to_string()),
            None => (rest, String::new()),
        };
        let matcher = if let Some(re) = pat.strip_prefix("re:") {
            match RegexBuilder::new(re).case_insensitive(true).build() {
                Ok(r) => Matcher::Regex(r),
                Err(e) => {
                    errors.push(format!("watchlist line {}: invalid regex: {e}", n + 1));
                    continue;
                }
            }
        } else {
            Matcher::Substring(pat.to_lowercase())
        };
        let label = if label.is_empty() {
            format!("matches watchlist pattern '{pat}'")
        } else {
            label
        };
        rules.push(WatchRule {
            severity: sev,
            matcher,
            pattern: pat.to_string(),
            label,
        });
    }
    (rules, errors)
}

/// Built-in rules: offensive tooling, credential access, anti-forensics,
/// encryption/anonymity tools and staging-style folder names. Matching is
/// done on individual path segments, so expect some false positives and
/// always verify in context.
pub const BUILTIN: &str = r#"
high: mimikatz | Credential theft tool (Mimikatz)
high: re:\b(lazagne|rubeus|kekeo|safetykatz|sharpdump|nanodump|pypykatz|sharpkatz) | Credential theft tool
high: re:\b(sharphound|bloodhound|adfind|adrecon|pingcastle) | Active Directory reconnaissance tool
high: re:\b(cobalt ?strike|metasploit|meterpreter|sliver-?server|brute ?ratel|covenant|mythic) | C2 / exploitation framework
high: re:\b(impacket|crackmapexec|netexec|evil-winrm|responder|inveigh) | Lateral movement / relay tooling
high: re:\b(procdump|nanodump|comsvcs|lsassy|dumpert) | LSASS dumping utility
medium: re:\b(psexec|paexec|psexesvc|remcom) | Remote execution utility (PsExec or clone)
medium: re:\b(nmap|masscan|advanced ?ip ?scanner|angry ?ip|netscan|softperfect) | Network scanner
medium: re:\b(rclone|megasync|megacmd|filezilla|winscp|restic) | Data transfer / exfiltration utility
medium: re:\b(anydesk|teamviewer|screenconnect|atera|splashtop|rustdesk|ngrok|chisel|plink) | Remote access / tunnelling tool
medium: re:\b(hashcat|johntheripper|john-the-ripper|thc-hydra|ophcrack) | Password cracking tool
medium: re:\b(ccleaner|bleachbit|privazer|sdelete|eraser ?\d|eraser$) | Anti-forensics / secure deletion tool
medium: re:\b(veracrypt|truecrypt|diskcryptor|axcrypt) | Encryption container software
medium: re:\b(tor ?browser|torbrowser) | Anonymisation software
medium: re:^(exfil|exfiltration|loot|staging|stage|dump|dumps|harvest|stolen)$ | Staging-style folder name
low: re:\b(keygen|cracked|warez) | Software piracy indicator
low: re:\b(passwords?|creds|credentials|confidential) | Sensitive-sounding folder name
low: re:\b(hacking|hacktools?|exploits?|payloads?|shellcode|rootkits?|keyloggers?|ransomware) | Offensive-security folder name
low: re:^(kali|parrot)$ | Offensive Linux distribution folder
"#;

pub fn builtin() -> Vec<WatchRule> {
    parse(BUILTIN).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_compile() {
        let (rules, errs) = parse(BUILTIN);
        assert!(errs.is_empty(), "{errs:?}");
        assert!(rules.len() > 15);
        assert!(rules.iter().any(|r| r.matches("mimikatz_trunk")));
        assert!(rules.iter().any(|r| r.matches("PsExec64")));
        assert!(!rules.iter().any(|r| r.matches("Documents")));
    }

    #[test]
    fn custom_rules() {
        let (rules, errs) = parse("high: secretproject | Project codename\nre:[ # bad\nfoo");
        assert_eq!(errs.len(), 1);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].severity, Severity::High);
        assert!(rules[0].matches("SecretProject"));
        assert_eq!(rules[1].severity, Severity::Low);
    }
}
