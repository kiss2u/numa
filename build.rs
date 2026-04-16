fn main() {
    let git_version = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| {
            let s = s.trim();
            let s = s.strip_prefix('v').unwrap_or(s);
            // "0.13.1"                     → clean tag  → "0.13.1"
            // "0.13.1-9-ga87f907"          → ahead      → "0.13.1+a87f907"
            // "0.13.1-9-ga87f907-dirty"    → dirty       → "0.13.1+a87f907-dirty"
            // "a87f907"                    → no tags     → "0.0.0+a87f907"
            // "a87f907-dirty"             → no tags     → "0.0.0+a87f907-dirty"
            if let Some((base, rest)) = s.split_once("-") {
                // Could be "0.13.1-9-ga87f907[-dirty]" or "a87f907-dirty"
                if base.contains('.') {
                    // Tagged: extract sha from "-N-gSHA[-dirty]"
                    let parts: Vec<&str> = rest.splitn(3, '-').collect();
                    match parts.as_slice() {
                        [_n, sha] => format!("{}+{}", base, sha.strip_prefix('g').unwrap_or(sha)),
                        [_n, sha, "dirty"] => {
                            format!("{}+{}-dirty", base, sha.strip_prefix('g').unwrap_or(sha))
                        }
                        _ => s.to_string(),
                    }
                } else {
                    // Untagged: "sha-dirty"
                    format!("0.0.0+{}", s)
                }
            } else if s.contains('.') {
                // Exact tag match: "0.13.1"
                s.to_string()
            } else {
                // Bare sha, no tags at all
                format!("0.0.0+{}", s)
            }
        });

    if let Some(v) = git_version {
        println!("cargo:rustc-env=NUMA_BUILD_VERSION={}", v);
    }

    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags/");
}
