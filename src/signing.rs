//! Report signing and verification (LT-1).
//!
//! Produces a `SignedReport` wrapper around `AgentReport` with an
//! Ed25519 signature over a canonical byte representation of the report.
//! The canonical form sorts all JSON object keys recursively so that
//! semantically identical reports sign to the same bytes regardless of
//! map iteration order.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use russh::keys::ssh_encoding::{Decode, Encode};
use russh::keys::ssh_key::{HashAlg, PrivateKey, PublicKey, SshSig};
use serde_json::Value;

use crate::models::AgentReport;

/// Domain separation string for signatures. Prevents a signature made for
/// one purpose from being replayed in another.
pub const REPORT_SIGNING_NAMESPACE: &str = "owlzops-mapper-report";

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to read signature: {0}")]
    SignatureFormat(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Wrapper containing the original report plus its signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SignedReport {
    pub report: AgentReport,
    /// Ed25519 signature over the canonical report bytes, base64-encoded.
    pub signature: String,
    /// Public key corresponding to the signing key, base64-encoded.
    pub public_key: String,
    /// Domain separation string used during signing/verification.
    pub namespace: String,
}

impl Default for SignedReport {
    fn default() -> Self {
        Self {
            report: AgentReport::default(),
            signature: String::new(),
            public_key: String::new(),
            namespace: REPORT_SIGNING_NAMESPACE.to_string(),
        }
    }
}

/// Recursively sort all JSON object keys (arrays are left untouched:
/// element order may be semantically significant, e.g. `load_average`).
fn sort_json_object_keys(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map.iter() {
                let mut v = v.clone();
                sort_json_object_keys(&mut v);
                sorted.insert(k.clone(), v);
            }
            // rebuild the map from sorted keys
            *map = serde_json::Map::from_iter(sorted);
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                sort_json_object_keys(item);
            }
        }
        _ => {}
    }
}

/// Canonical byte representation of an `AgentReport`.
///
/// JSON object keys are sorted recursively; array order is preserved.
pub fn canonicalize(report: &AgentReport) -> Result<Vec<u8>, SigningError> {
    let mut value = serde_json::to_value(report)?;
    sort_json_object_keys(&mut value);
    Ok(serde_json::to_vec(&value)?)
}

/// Sign a report using an Ed25519 private key.
pub fn sign_report(
    report: &AgentReport,
    private_key: &PrivateKey,
) -> Result<SignedReport, SigningError> {
    let canonical = canonicalize(report)?;
    let sig = private_key
        .sign(REPORT_SIGNING_NAMESPACE, HashAlg::Sha512, &canonical)
        .map_err(|e| SigningError::Sign(e.to_string()))?;

    let mut sig_bytes = Vec::new();
    sig.encode(&mut sig_bytes)
        .map_err(|e| SigningError::Sign(e.to_string()))?;

    let pub_bytes = private_key
        .public_key()
        .to_bytes()
        .map_err(|e| SigningError::Sign(e.to_string()))?;

    Ok(SignedReport {
        report: report.clone(),
        signature: BASE64.encode(sig_bytes),
        public_key: BASE64.encode(pub_bytes),
        namespace: REPORT_SIGNING_NAMESPACE.to_string(),
    })
}

/// Verify a signed report.
///
/// The signature is checked against the canonical bytes of the embedded
/// report using the namespace stored in `signed.namespace`.
pub fn verify_report(signed: &SignedReport) -> Result<bool, SigningError> {
    let canonical = canonicalize(&signed.report)?;

    let sig_bytes = BASE64.decode(&signed.signature)?;
    let mut sig_reader = &sig_bytes[..];
    let sig = SshSig::decode(&mut sig_reader)
        .map_err(|e| SigningError::SignatureFormat(e.to_string()))?;

    let pub_bytes = BASE64.decode(&signed.public_key)?;
    let public_key = PublicKey::from_bytes(&pub_bytes)
        .map_err(|e| SigningError::SignatureFormat(e.to_string()))?;

    public_key
        .verify(&signed.namespace, &canonical, &sig)
        .map(|_| true)
        .map_err(|e| SigningError::Verify(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::Algorithm;

    fn test_report() -> AgentReport {
        AgentReport {
            scan_id: "test-scan".into(),
            version: "0.5.37".into(),
            ..Default::default()
        }
    }

    #[test]
    fn canonicalize_is_deterministic_across_map_iteration() {
        let mut json = serde_json::json!({
            "z": 1,
            "a": [ {"y": 2, "x": 3}, {"x": 4, "y": 5} ],
            "m": { "c": "v", "b": "u" }
        });
        let orig = json.clone();
        sort_json_object_keys(&mut json);

        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(keys, vec!["a", "m", "z"]);

        let m_keys: Vec<&str> = json["m"]
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(m_keys, vec!["b", "c"]);

        assert_eq!(json["a"][0]["y"], 2);
        assert_eq!(json["a"][1]["x"], 4);

        let mut json2 = orig.clone();
        sort_json_object_keys(&mut json2);
        assert_eq!(json, json2);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = rand::rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen");

        let report = test_report();
        let signed = sign_report(&report, &key).expect("sign");

        assert!(verify_report(&signed).expect("verify"));
    }

    #[test]
    fn tampered_report_fails_verification() {
        let mut rng = rand::rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen");

        let report = test_report();
        let mut signed = sign_report(&report, &key).expect("sign");

        signed.report.host.hostname = "evil".into();

        assert!(verify_report(&signed).is_err());
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let mut rng = rand::rng();
        let key1 = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen1");
        let key2 = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen2");

        let report = test_report();
        let mut signed = sign_report(&report, &key1).expect("sign");

        signed.public_key = BASE64.encode(key2.public_key().to_bytes().expect("pub bytes"));

        assert!(verify_report(&signed).is_err());
    }
}
