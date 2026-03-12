use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tracing::info;

static LICENSE_STATE: RwLock<Option<LicenseInfo>> = RwLock::new(None);

const GUMROAD_VERIFY_URL: &str = "https://api.gumroad.com/v2/licenses/verify";
const RENEWAL_GRACE_DAYS: i64 = 7;

pub fn renewal_grace_secs() -> u64 {
    (RENEWAL_GRACE_DAYS * 24 * 60 * 60) as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    Active,
    Grace,
    Expired,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        LicenseStatus::Active
    }
}

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
    #[serde(default)]
    pub status: LicenseStatus,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub grace_expires_at: Option<u64>,
    #[serde(default)]
    pub grace_reason: Option<String>,
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

fn parse_iso_to_epoch(s: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(s)
        .or_else(|_| DateTime::parse_from_rfc2822(s))
        .map(|dt| dt.timestamp().max(0) as u64)
        .ok()
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

pub async fn verify_license(product_id: &str, license_key: &str) -> Result<LicenseInfo, String> {
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

    let purchase = parsed.purchase.ok_or("No purchase data in response")?;

    if purchase.refunded {
        return Err("This license has been refunded".to_string());
    }
    if purchase.chargebacked {
        return Err("This license has been chargebacked".to_string());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (status, valid, expires_at, grace_expires_at, grace_reason) =
        if let Some(ts) = purchase
            .subscription_cancelled_at
            .as_ref()
            .or(purchase.subscription_failed_at.as_ref())
        {
            let expiry = parse_iso_to_epoch(ts).unwrap_or(now);
            let grace_end = expiry + renewal_grace_secs();
            let reason = if purchase.subscription_cancelled_at.is_some() {
                "subscription_cancelled"
            } else {
                "payment_failed"
            };

            if now <= grace_end {
                (
                    LicenseStatus::Grace,
                    true,
                    Some(expiry),
                    Some(grace_end),
                    Some(reason.to_string()),
                )
            } else {
                (
                    LicenseStatus::Expired,
                    false,
                    Some(expiry),
                    Some(grace_end),
                    Some(reason.to_string()),
                )
            }
        } else {
            (
                LicenseStatus::Active,
                true,
                None,
                None,
                None,
            )
        };

    let info = LicenseInfo {
        license_key: license_key.to_string(),
        email: purchase.email.unwrap_or_default(),
        product_name: purchase.product_name.unwrap_or_default(),
        variant: purchase.variants.unwrap_or_default(),
        valid,
        uses: 0,
        created_at: purchase.created_at.unwrap_or_default(),
        verified_at: now,
        status,
        expires_at,
        grace_expires_at,
        grace_reason,
    };

    set_license_info(Some(info.clone()));
    info!(
        "License verified: status={:?} valid={} for {}",
        info.status, info.valid, info.email
    );

    Ok(info)
}

pub fn deactivate_license() {
    info!("License deactivated");
    set_license_info(None);
}

pub fn restore_cached_license(info: LicenseInfo) {
    let offline_grace_secs = 7 * 24 * 60 * 60; // 7 days offline grace
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let should_restore = match &info.status {
        LicenseStatus::Active => info.valid && (now.saturating_sub(info.verified_at) < offline_grace_secs),
        LicenseStatus::Grace => {
            info.valid
                && info.grace_expires_at.map_or(false, |g| now <= g)
        }
        LicenseStatus::Expired => false,
    };

    if should_restore {
        info!("Restoring cached license (within grace period)");
        set_license_info(Some(info));
    } else {
        info!("Cached license expired, needs re-verification");
    }
}
