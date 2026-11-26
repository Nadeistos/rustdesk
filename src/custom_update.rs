//! Automatic updates of a custom build from its own GitHub releases.
//!
//! Enabled when the build sets `UPDATE_REPO` ("owner/name") and `UPDATE_PUBLIC_KEY`
//! (base64 Ed25519 public key). Each release then carries one signed metadata file per
//! edition, `rustdesk-update-<UPDATE_CHANNEL>.json` and its `.sig`, so a client build only
//! ever installs the client edition and a technician build the technician edition.

use hbb_common::{anyhow::anyhow, ResultType};

pub(crate) const KEY_ID: &str = "custom-build-update";
const DEFAULT_CHANNEL: &str = "client";

fn configured_repo() -> Option<&'static str> {
    option_env!("UPDATE_REPO").filter(|s| s.split('/').count() == 2 && !s.contains(' '))
}

/// Public key of the custom update channel, if this build updates from its own releases.
pub(crate) fn public_key() -> Option<[u8; 32]> {
    configured_repo()?;
    let key = crate::decode64(option_env!("UPDATE_PUBLIC_KEY")?.trim()).ok()?;
    key.try_into().ok()
}

/// "owner/name" of the GitHub repository this build updates from.
pub(crate) fn repo() -> Option<&'static str> {
    public_key()?;
    configured_repo()
}

pub(crate) fn is_repo(owner: &str, name: &str) -> bool {
    repo() == Some(format!("{owner}/{name}").as_str())
}

pub(crate) fn channel() -> &'static str {
    option_env!("UPDATE_CHANNEL")
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_CHANNEL)
}

pub(crate) fn metadata_file_name() -> String {
    if repo().is_some() {
        format!("rustdesk-update-{}.json", channel())
    } else {
        "rustdesk-update.json".to_owned()
    }
}

/// Release page URL of the latest published release, e.g.
/// `https://github.com/owner/name/releases/tag/1.5.301`.
pub(crate) async fn latest_release_page_url(repo: &str) -> ResultType<String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = crate::hbbs_http::create_http_client_async(
        hbb_common::tls::TlsType::Rustls,
        false,
    );
    let response = client
        .get(&url)
        .header("User-Agent", "custom-build-updater")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "Custom update check failed with HTTP status: {}",
            response.status()
        ));
    }
    let release: serde_json::Value = serde_json::from_slice(&response.bytes().await?)?;
    release["html_url"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Latest release has no html_url"))
}
