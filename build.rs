use std::process::Command;

fn main() {
    // Get the current timestamp
    let timestamp = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);

    // Get the git SHA
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Failed to get git SHA");
    let git_sha = String::from_utf8(output.stdout).expect("Failed to parse git SHA");
    println!("cargo:rustc-env=GIT_SHA={}", git_sha.trim());

    // Get the git tag
    let tag_output = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .expect("Failed to get git tag");
    let git_tag = String::from_utf8(tag_output.stdout).expect("Failed to parse git tag");
    println!("cargo:rustc-env=GIT_TAG={}", git_tag.trim());
}
