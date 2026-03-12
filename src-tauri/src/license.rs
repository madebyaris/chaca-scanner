use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tracing::info;

static LICENSE_STATE: RwLock<Option<LicenseInfo>> = RwLock::new(None);

const GUMROAD_VERIFY_URL: &str = "https://api.gumroad.com/v2/licenses/verify";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub license_key: String,
    pub email: String,
    pub product_name: String,
    pub variant: String,
    pub valid: bool,
    pub uses: u32,
    pub created_at: String,
    pub verified_at: u64,
}

#[derive(Debug, Deserialize)]
struct GumroadResponse {
    success: bool,
    purchase: Option<GumroadPurchase>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GumroadPurchase {
    email: Option<String>,
    product_name: Option<String>,
    #[serde(default)]
    variants: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    license_key: Option<String>,
    created_at: Option<String>,
    #[serde(default)]
    refunded: bool,
    #[serde(default)]
    chargebacked: bool,
    #[serde(default)]
    subscription_cancelled_at: Option<String>,
    #[serde(default)]
    subscription_failed_at: Option<String>,
}

pub fn is_pro() -> bool {
    LICENSE_STATE
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(|info| info.valid))
        .unwrap_or(false)
}

pub fn get_license_info() -> Option<LicenseInfo> {
    LICENSE_STATE.read().ok().and_then(|guard| guard.clone())
}

pub fn set_license_info(info: Option<LicenseInfo>) {
    if let Ok(mut guard) = LICENSE_STATE.write() {
        *guard = info;
    }
}

pub async fn verify_license(
    product_id: &str,
    license_key: &str,
) -> Result<LicenseInfo, String> {
    info!("Verifying license key against Gumroad API");

    let client = reqwest::Client::new();
    let resp = client
        .post(GUMROAD_VERIFY_URL)
        .form(&[
            ("product_id", product_id),
            ("license_key", license_key),
            ("increment_uses_count", "false"),
        ])
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    let _status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let parsed: GumroadResponse =
        serde_json::from_str(&body).map_err(|e| format!("Invalid response: {}", e))?;

    if !parsed.success {
        return Err(parsed
            .message
            .unwrap_or_else(|| "License verification failed".to_string()));
    }

    let purchase = parsed
        .purchase
        .ok_or("No purchase data in response")?;

    if purchase.refunded {
        return Err("This license has been refunded".to_string());
    }
    if purchase.chargebacked {
        return Err("This license has been chargebacked".to_string());
    }
    if purchase.subscription_cancelled_at.is_some() {
        return Err("This subscription has been cancelled".to_string());
    }
    if purchase.subscription_failed_at.is_some() {
        return Err("This subscription payment has failed".to_string());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let info = LicenseInfo {
        license_key: license_key.to_string(),
        email: purchase.email.unwrap_or_default(),
        product_name: purchase.product_name.unwrap_or_default(),
        variant: purchase.variants.unwrap_or_default(),
        valid: true,
        uses: 0,
        created_at: purchase.created_at.unwrap_or_default(),
        verified_at: now,
    };

    set_license_info(Some(info.clone()));
    info!("License verified successfully for {}", info.email);

    Ok(info)
}

pub fn deactivate_license() {
    info!("License deactivated");
    set_license_info(None);
}

pub fn restore_cached_license(info: LicenseInfo) {
    let grace_period_secs = 7 * 24 * 60 * 60; // 7 days offline grace
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if info.valid && (now - info.verified_at) < grace_period_secs {
        info!("Restoring cached license (within grace period)");
        set_license_info(Some(info));
    } else {
        info!("Cached license expired, needs re-verification");
    }
}
