//! Live protocol drivers for Amazon S3 (SigV4 REST XML), WebDAV (`PROPFIND`/`GET`/`PUT`/`MKCOL`/`DELETE`/`MOVE`/`COPY`),
//! FTP/FTPS, and SMB (`GAP-01`).
//!
//! All HTTP/FTP credentials and authorization headers are passed to `curl --config -` via piped `stdin`
//! (or a `0600` temp authfile for `smbclient`), ensuring secrets never appear in process `argv` (`SEC-06`/`SEC-07`).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::SystemTime;

use manifold_config::{ConnectionProfile, ProtocolType};
use manifold_vfs::{
    create_secure_temp_file, infer_file_kind, system_time_to_utc_civil, ColorLabel, FileMetadata,
    VfsError, VolumeStats,
};
use sha2::{Digest, Sha256};

use crate::parse_ls_aln_output;

/// Computes `HMAC-SHA256(key, message)` with the audited RustCrypto `hmac`
/// crate (F-20; replaces the previous hand-rolled construction).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    // `new_from_slice` only errors on impossible key lengths for HMAC.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_encode(&digest)
}

fn uri_encode_s3(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for b in input.bytes() {
        let is_unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if is_unreserved || (!encode_slash && b == b'/') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn escape_curl_config_val(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 2);
    out.push('"');
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' | '\n' | '\0' => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn run_curl_with_stdin_config(
    config_lines: &[String],
    extra_args: &[&str],
) -> Result<Vec<u8>, VfsError> {
    let mut child = Command::new("curl")
        .args(["-sS", "--fail-with-body", "--connect-timeout", "10"])
        .args(extra_args)
        .args(["--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VfsError::NetworkError(format!("Failed to execute curl: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        let payload = config_lines.join("\n") + "\n";
        let _ = stdin.write_all(payload.as_bytes());
    }
    let out = child
        .wait_output_or_wait()
        .map_err(|e| VfsError::NetworkError(format!("curl execution failed: {e}")))?;
    if !out.status.success() {
        let stderr_txt = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout_txt = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr_txt.is_empty() {
            stderr_txt
        } else if !stdout_txt.is_empty() {
            stdout_txt
        } else {
            format!("HTTP/transfer failed with status {}", out.status)
        };
        return Err(VfsError::NetworkError(detail));
    }
    Ok(out.stdout)
}

trait ChildWaitHelper {
    fn wait_output_or_wait(self) -> std::io::Result<std::process::Output>;
}

impl ChildWaitHelper for std::process::Child {
    fn wait_output_or_wait(self) -> std::io::Result<std::process::Output> {
        self.wait_with_output()
    }
}

// ============================================================================
// 1. Amazon S3 & S3-Compatible (AWS Signature Version 4)
// ============================================================================

struct S3EndpointSpec {
    host_header: String,
    base_url: String,
    bucket_prefix: String,
    region: String,
}

fn resolve_s3_endpoint(profile: &ConnectionProfile) -> Result<S3EndpointSpec, VfsError> {
    // F-31: Azure Blob uses Shared Key / Entra ID authentication, which is
    // fundamentally different from AWS SigV4. Routing it through the S3
    // driver only produced confusing signature errors; fail honestly.
    if profile.protocol == ProtocolType::AzureBlob {
        return Err(VfsError::UnsupportedOperation(
            "Azure Blob Storage requires Shared Key/Entra authentication, which is not \
             implemented. The S3 driver covers AWS S3, S3-compatible endpoints, and GCS \
             interoperability HMAC keys."
                .to_string(),
        ));
    }
    let bucket = profile
        .bucket
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            profile
                .base_path
                .trim_matches('/')
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| VfsError::InvalidPath("Missing S3 bucket name".to_string()))?;
    let region = profile
        .region
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("us-east-1")
        .to_string();

    let raw_ep = profile
        .endpoint
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| profile.host.as_deref().filter(|s| !s.trim().is_empty()))
        .unwrap_or("");

    if raw_ep.is_empty() && profile.protocol == ProtocolType::Gcs {
        // GCS interoperability mode speaks the S3 XML API path-style at the
        // global endpoint with HMAC (GOOG...) access keys.
        let host = "storage.googleapis.com".to_string();
        return Ok(S3EndpointSpec {
            base_url: format!("https://{host}"),
            host_header: host,
            bucket_prefix: format!("/{bucket}"),
            region,
        });
    }
    if raw_ep.is_empty() || raw_ep.contains("amazonaws.com") {
        let host = format!("{bucket}.s3.{region}.amazonaws.com");
        Ok(S3EndpointSpec {
            base_url: format!("https://{host}"),
            host_header: host,
            bucket_prefix: String::new(),
            region,
        })
    } else {
        let (scheme, rest) = if let Some(r) = raw_ep.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = raw_ep.strip_prefix("http://") {
            ("http", r)
        } else {
            ("https", raw_ep)
        };
        let host = rest.trim_end_matches('/');
        if host.contains('/') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            let msg = format!("Invalid S3 endpoint host: {raw_ep}");
            return Err(VfsError::InvalidPath(msg));
        }
        Ok(S3EndpointSpec {
            base_url: format!("{scheme}://{host}"),
            host_header: host.to_string(),
            bucket_prefix: format!("/{bucket}"),
            region,
        })
    }
}

/// Parameters for computing an AWS Signature Version 4 header block.
pub struct S3SigV4Params<'a> {
    pub method: &'a str,
    pub host_header: &'a str,
    pub canonical_uri: &'a str,
    pub canonical_query: &'a str,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub payload_sha256_hex: &'a str,
    pub amz_date: &'a str,
}

/// Builds AWS SigV4 headers (`Authorization`, `x-amz-date`, `x-amz-content-sha256`) for an S3 request.
pub fn build_s3_sigv4_headers(p: &S3SigV4Params<'_>) -> Vec<String> {
    let method = p.method;
    let host_header = p.host_header;
    let canonical_uri = p.canonical_uri;
    let canonical_query = p.canonical_query;
    let region = p.region;
    let access_key = p.access_key;
    let secret_key = p.secret_key;
    let payload_sha256_hex = p.payload_sha256_hex;
    let amz_date = p.amz_date;
    let date_stamp = &amz_date[..8.min(amz_date.len())];
    let canonical_headers = format!(
        "host:{host_header}\nx-amz-content-sha256:{payload_sha256_hex}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let req_top = format!("{method}\n{canonical_uri}\n{canonical_query}");
    let req_bot = format!("{canonical_headers}\n{signed_headers}\n{payload_sha256_hex}");
    let canonical_request = format!("{req_top}\n{req_bot}");
    let canon_hash = sha256_hex(canonical_request.as_bytes());
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canon_hash}");

    let k_secret = format!("AWS4{secret_key}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let sig = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let cred_part = format!("Credential={access_key}/{credential_scope}");
    let auth_val =
        format!("AWS4-HMAC-SHA256 {cred_part}, SignedHeaders={signed_headers}, Signature={sig}");
    vec![
        format!(
            "header = {}",
            escape_curl_config_val(&format!("Host: {host_header}"))
        ),
        format!(
            "header = {}",
            escape_curl_config_val(&format!("x-amz-date: {amz_date}"))
        ),
        format!(
            "header = {}",
            escape_curl_config_val(&format!("x-amz-content-sha256: {payload_sha256_hex}"))
        ),
        format!(
            "header = {}",
            escape_curl_config_val(&format!("Authorization: {auth_val}"))
        ),
    ]
}

fn current_amz_date() -> String {
    let now = SystemTime::now();
    let (y, m, d, hh, mm) = system_time_to_utc_civil(now);
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| (dur.as_secs() % 60) as u32)
        .unwrap_or(0);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{secs:02}Z")
}

pub fn s3_list_directory(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<FileMetadata>, VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let access_key = profile.username.trim();
    let secret_key = secret.unwrap_or("").trim();
    if access_key.is_empty() || secret_key.is_empty() {
        return Err(VfsError::AuthFailed(
            "S3 connection requires Access Key ID and Secret Access Key".to_string(),
        ));
    }

    let prefix_rel = norm_path.trim_matches('/');
    let s3_prefix = if prefix_rel.is_empty() {
        String::new()
    } else {
        format!("{prefix_rel}/")
    };
    let access_key_owned = access_key.to_string();
    let secret_key_owned = secret.unwrap_or("").trim().to_string();
    let mut entries = Vec::new();
    let mut token: Option<String> = None;
    loop {
        // F-5: ListObjectsV2 returns at most 1000 keys per page; keep
        // fetching with the continuation token until not truncated.
        let xml = s3_list_page(
            &ep,
            &access_key_owned,
            &secret_key_owned,
            &s3_prefix,
            true,
            token.as_deref(),
        )?;
        entries.extend(parse_s3_list_xml(&xml, norm_path, &s3_prefix, access_key));
        token = s3_next_token(&xml);
        if token.is_none() {
            break;
        }
    }
    Ok(entries)
}

/// Fetches one `ListObjectsV2` page. Query parameters are assembled in the
/// lexicographic order AWS SigV4 requires; `delimiter` selects one-level
/// listings and `token` continues a truncated listing (F-5).
fn s3_list_page(
    ep: &S3EndpointSpec,
    access_key: &str,
    secret_key: &str,
    s3_prefix: &str,
    delimiter: bool,
    token: Option<&str>,
) -> Result<String, VfsError> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = token {
        parts.push(format!("continuation-token={}", uri_encode_s3(t, true)));
    }
    if delimiter {
        parts.push("delimiter=%2F".to_string());
    }
    parts.push("list-type=2".to_string());
    parts.push(format!("prefix={}", uri_encode_s3(s3_prefix, true)));
    let canonical_query = parts.join("&");
    let canonical_uri = if ep.bucket_prefix.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", ep.bucket_prefix)
    };
    let url = format!("{}{canonical_uri}?{canonical_query}", ep.base_url);
    let empty_sha = sha256_hex(b"");
    let amz_date = current_amz_date();

    let mut cfg = build_s3_sigv4_headers(&S3SigV4Params {
        method: "GET",
        host_header: &ep.host_header,
        canonical_uri: &canonical_uri,
        canonical_query: &canonical_query,
        region: &ep.region,
        access_key,
        secret_key,
        payload_sha256_hex: &empty_sha,
        amz_date: &amz_date,
    });
    cfg.push(format!("url = {}", escape_curl_config_val(&url)));
    let xml_bytes = run_curl_with_stdin_config(&cfg, &[])?;
    Ok(String::from_utf8_lossy(&xml_bytes).into_owned())
}

/// Returns the continuation token when a `ListObjectsV2` page was
/// truncated, `None` otherwise (F-5).
fn s3_next_token(xml: &str) -> Option<String> {
    if xml.contains("<IsTruncated>true</IsTruncated>") {
        extract_xml_tag_text(xml, "NextContinuationToken")
    } else {
        None
    }
}

/// Parses an AWS S3 `ListObjectsV2` XML response into [`FileMetadata`] entries.
pub fn parse_s3_list_xml(
    xml: &str,
    dir_norm: &str,
    s3_prefix: &str,
    owner: &str,
) -> Vec<FileMetadata> {
    let mut out = Vec::new();
    let trimmed_dir = dir_norm.trim_end_matches('/');

    // 1. Extract CommonPrefixes -> Folders
    let mut rem = xml;
    while let Some(start) = rem.find("<CommonPrefixes>") {
        let after = &rem[start + 16..];
        let Some(end) = after.find("</CommonPrefixes>") else {
            break;
        };
        let block = &after[..end];
        if let Some(pref) = extract_xml_tag_text(block, "Prefix") {
            let rel = pref.strip_prefix(s3_prefix).unwrap_or(&pref);
            let name = rel.trim_matches('/').to_string();
            if !name.is_empty() && !name.contains('/') {
                let full_path = format!("{trimmed_dir}/{name}");
                out.push(FileMetadata {
                    is_hidden: name.starts_with('.'),
                    name,
                    path: full_path,
                    extension: None,
                    kind: "Folder".to_string(),
                    size: None,
                    is_dir: true,
                    is_symlink: false,
                    is_locked: false,
                    hide_extension: false,
                    color_label: ColorLabel::None,
                    modified: Some(SystemTime::now()),
                    created: Some(SystemTime::now()),
                    added: Some(SystemTime::now()),
                    permissions: 0o755,
                    owner: Some(owner.to_string()),
                    group: Some("s3".to_string()),
                });
            }
        }
        rem = &after[end + 17..];
    }

    // 2. Extract Contents -> Files
    let mut rem_c = xml;
    while let Some(start) = rem_c.find("<Contents>") {
        let after = &rem_c[start + 10..];
        let Some(end) = after.find("</Contents>") else {
            break;
        };
        let block = &after[..end];
        if let Some(key) = extract_xml_tag_text(block, "Key") {
            let rel = key.strip_prefix(s3_prefix).unwrap_or(&key);
            if !rel.is_empty() && !rel.ends_with('/') && !rel.contains('/') {
                let name = rel.to_string();
                let size = extract_xml_tag_text(block, "Size")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let (extension, kind) = infer_file_kind(&name, false);
                let full_path = format!("{trimmed_dir}/{name}");
                out.push(FileMetadata {
                    is_hidden: name.starts_with('.'),
                    name,
                    path: full_path,
                    extension,
                    kind,
                    size: Some(size),
                    is_dir: false,
                    is_symlink: false,
                    is_locked: false,
                    hide_extension: false,
                    color_label: ColorLabel::None,
                    modified: Some(SystemTime::now()),
                    created: Some(SystemTime::now()),
                    added: Some(SystemTime::now()),
                    permissions: 0o644,
                    owner: Some(owner.to_string()),
                    group: Some("s3".to_string()),
                });
            }
        }
        rem_c = &after[end + 11..];
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

pub fn s3_read_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<u8>, VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let key = norm_path.trim_start_matches('/');
    let encoded_key = uri_encode_s3(key, false);
    let canonical_uri = format!("{}/{encoded_key}", ep.bucket_prefix);
    let url = format!("{}{canonical_uri}", ep.base_url);
    let empty_sha = sha256_hex(b"");
    let amz_date = current_amz_date();
    let mut cfg = build_s3_sigv4_headers(&S3SigV4Params {
        method: "GET",
        host_header: &ep.host_header,
        canonical_uri: &canonical_uri,
        canonical_query: "",
        region: &ep.region,
        access_key: profile.username.trim(),
        secret_key: secret.unwrap_or("").trim(),
        payload_sha256_hex: &empty_sha,
        amz_date: &amz_date,
    });
    cfg.push(format!("url = {}", escape_curl_config_val(&url)));
    run_curl_with_stdin_config(&cfg, &[])
}

pub fn s3_write_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    data: &[u8],
) -> Result<(), VfsError> {
    let (tmp_path, mut tmp_file) = create_secure_temp_file("s3_io", "s3-put", ".bin")?;
    tmp_file.write_all(data)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    let res = s3_upload_file(profile, secret, &tmp_path, norm_path);
    let _ = fs::remove_file(&tmp_path);
    res
}

pub fn s3_upload_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    local_path: &Path,
    norm_path: &str,
) -> Result<(), VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let key = norm_path.trim_start_matches('/');
    let encoded_key = uri_encode_s3(key, false);
    let canonical_uri = format!("{}/{encoded_key}", ep.bucket_prefix);
    let url = format!("{}{canonical_uri}", ep.base_url);
    let amz_date = current_amz_date();
    let payload_sha = "UNSIGNED-PAYLOAD";
    let mut cfg = build_s3_sigv4_headers(&S3SigV4Params {
        method: "PUT",
        host_header: &ep.host_header,
        canonical_uri: &canonical_uri,
        canonical_query: "",
        region: &ep.region,
        access_key: profile.username.trim(),
        secret_key: secret.unwrap_or("").trim(),
        payload_sha256_hex: payload_sha,
        amz_date: &amz_date,
    });
    cfg.push(format!("url = {}", escape_curl_config_val(&url)));
    cfg.push(format!(
        "upload-file = {}",
        escape_curl_config_val(&local_path.to_string_lossy())
    ));
    let _ = run_curl_with_stdin_config(&cfg, &["-X", "PUT"])?;
    Ok(())
}

/// Runs a curl download to `local_path` atomically (F-3): the transfer is
/// written to a unique temp file in the destination directory and only
/// renamed into place after curl reported success, so a failed or
/// interrupted transfer never truncates an existing file. The temp file is
/// removed when the transfer fails.
fn curl_download_atomically(
    cfg: &mut Vec<String>,
    local_path: &Path,
    extra_args: &[&str],
) -> Result<(), VfsError> {
    static DL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = DL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = local_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let tmp = dir.join(format!(".manifold-dl-{}-{}.part", std::process::id(), seq));
    cfg.push(format!(
        "output = {}",
        escape_curl_config_val(&tmp.to_string_lossy())
    ));
    if let Err(e) = run_curl_with_stdin_config(cfg, extra_args) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(f) = fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    if let Err(e) = fs::rename(&tmp, local_path) {
        let _ = fs::remove_file(&tmp);
        return Err(VfsError::IoError(e));
    }
    if let Some(parent) = local_path.parent() {
        manifold_vfs::sync_dir(parent).map_err(VfsError::IoError)?;
    }
    Ok(())
}

pub fn s3_download_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    local_path: &Path,
) -> Result<(), VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let key = norm_path.trim_start_matches('/');
    let encoded_key = uri_encode_s3(key, false);
    let canonical_uri = format!("{}/{encoded_key}", ep.bucket_prefix);
    let url = format!("{}{canonical_uri}", ep.base_url);
    let empty_sha = sha256_hex(b"");
    let amz_date = current_amz_date();
    let mut cfg = build_s3_sigv4_headers(&S3SigV4Params {
        method: "GET",
        host_header: &ep.host_header,
        canonical_uri: &canonical_uri,
        canonical_query: "",
        region: &ep.region,
        access_key: profile.username.trim(),
        secret_key: secret.unwrap_or("").trim(),
        payload_sha256_hex: &empty_sha,
        amz_date: &amz_date,
    });
    cfg.push(format!("url = {}", escape_curl_config_val(&url)));
    curl_download_atomically(&mut cfg, local_path, &[])
}

pub fn s3_create_dir(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let folder_key = format!("{}/", norm_path.trim_matches('/'));
    s3_write_bytes(profile, secret, &folder_key, b"")
}

pub fn s3_remove(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let key = norm_path.trim_start_matches('/');
    s3_delete_key(profile, secret, &ep, key)
}

/// Recursively deletes every object under `norm_path/` plus the directory
/// marker itself (F-4). Previously only the addressed key was deleted, so
/// child objects survived and the "directory" reappeared on the next
/// listing. Per-object failures are collected and reported; the operation
/// continues with the remaining keys.
pub fn s3_remove_tree(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let ep = resolve_s3_endpoint(profile)?;
    let access_key = profile.username.trim();
    let secret_key = secret.unwrap_or("").trim();
    let dir_prefix = format!("{}/", norm_path.trim_matches('/'));
    let mut token: Option<String> = None;
    let mut failures: Vec<String> = Vec::new();
    loop {
        let xml = s3_list_page(
            &ep,
            access_key,
            secret_key,
            &dir_prefix,
            false,
            token.as_deref(),
        )?;
        let mut rem = xml.as_str();
        while let Some(start) = rem.find("<Contents>") {
            let after = &rem[start + 10..];
            let Some(end) = after.find("</Contents>") else {
                break;
            };
            let block = &after[..end];
            if let Some(key) = extract_xml_tag_text(block, "Key") {
                if let Err(e) = s3_delete_key(profile, secret, &ep, &key) {
                    failures.push(format!("{key}: {e}"));
                }
            }
            rem = &after[end + 11..];
        }
        token = s3_next_token(&xml);
        if token.is_none() {
            break;
        }
    }
    // The marker key may not exist (some tools omit it); S3 DELETE is
    // idempotent, so a failure here is not fatal when children were deleted.
    let marker_res = s3_delete_key(profile, secret, &ep, &dir_prefix);
    if !failures.is_empty() {
        return Err(VfsError::OperationFailed(
            norm_path.to_string(),
            format!(
                "failed to delete {} object(s): {}",
                failures.len(),
                failures.join("; ")
            ),
        ));
    }
    marker_res
}

fn s3_delete_key(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    ep: &S3EndpointSpec,
    key: &str,
) -> Result<(), VfsError> {
    let encoded_key = uri_encode_s3(key, false);
    let canonical_uri = format!("{}/{encoded_key}", ep.bucket_prefix);
    let url = format!("{}{canonical_uri}", ep.base_url);
    let empty_sha = sha256_hex(b"");
    let amz_date = current_amz_date();
    let mut cfg = build_s3_sigv4_headers(&S3SigV4Params {
        method: "DELETE",
        host_header: &ep.host_header,
        canonical_uri: &canonical_uri,
        canonical_query: "",
        region: &ep.region,
        access_key: profile.username.trim(),
        secret_key: secret.unwrap_or("").trim(),
        payload_sha256_hex: &empty_sha,
        amz_date: &amz_date,
    });
    cfg.push(format!("url = {}", escape_curl_config_val(&url)));
    let _ = run_curl_with_stdin_config(&cfg, &["-X", "DELETE"])?;
    Ok(())
}

// ============================================================================
// 2. WebDAV (`PROPFIND`, `GET`, `PUT`, `MKCOL`, `DELETE`, `MOVE`, `COPY`)
// ============================================================================

fn resolve_webdav_url(profile: &ConnectionProfile, norm_path: &str) -> Result<String, VfsError> {
    let raw_host = profile
        .endpoint
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| profile.host.as_deref().filter(|s| !s.trim().is_empty()))
        .ok_or_else(|| VfsError::InvalidPath("Missing WebDAV server host/URL".to_string()))?
        .trim();
    let base = if raw_host.starts_with("http://") || raw_host.starts_with("https://") {
        raw_host.trim_end_matches('/').to_string()
    } else {
        let port_part = profile
            .port
            .filter(|&p| p != 80 && p != 443)
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        let scheme = if profile.port == Some(80) {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{}{port_part}", raw_host.trim_end_matches('/'))
    };
    let clean_rel = norm_path.trim_start_matches('/');
    if clean_rel.is_empty() {
        Ok(format!("{base}/"))
    } else {
        let encoded = uri_encode_s3(clean_rel, false);
        Ok(format!("{base}/{encoded}"))
    }
}

fn webdav_auth_config(profile: &ConnectionProfile, secret: Option<&str>, url: &str) -> Vec<String> {
    let mut cfg = vec![format!("url = {}", escape_curl_config_val(url))];
    if !profile.username.trim().is_empty() {
        let user_pass = format!("{}:{}", profile.username.trim(), secret.unwrap_or(""));
        cfg.push(format!("user = {}", escape_curl_config_val(&user_pass)));
    }
    cfg
}

pub fn webdav_list_directory(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<FileMetadata>, VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let mut cfg = webdav_auth_config(profile, secret, &url);
    cfg.push("header = \"Depth: 1\"".to_string());
    cfg.push("header = \"Content-Type: application/xml; charset=utf-8\"".to_string());
    let xml_bytes = run_curl_with_stdin_config(&cfg, &["-X", "PROPFIND"])?;
    let xml_str = String::from_utf8_lossy(&xml_bytes);
    Ok(parse_webdav_propfind_xml(
        &xml_str,
        norm_path,
        &profile.username,
    ))
}

/// Parses a WebDAV `PROPFIND` `207 Multi-Status` XML response into [`FileMetadata`] items.
pub fn parse_webdav_propfind_xml(xml: &str, dir_norm: &str, owner: &str) -> Vec<FileMetadata> {
    let mut out = Vec::new();
    let trimmed_dir = dir_norm.trim_end_matches('/');
    let mut first = true;

    // Tag-agnostic scanning across `<d:response>`, `<D:response>`, or `<response>` blocks
    let mut cursor = 0usize;
    while let Some(rel_idx) = xml[cursor..].find("response>") {
        let tag_end = cursor + rel_idx + 9;
        // Check if it was an opening tag (not `</...response>`)
        let prefix_slice = &xml[cursor..cursor + rel_idx];
        let is_closing = prefix_slice.ends_with("</")
            || prefix_slice.ends_with("</d:")
            || prefix_slice.ends_with("</D:");
        if is_closing {
            cursor = tag_end;
            continue;
        }
        let Some(close_rel) = xml[tag_end..].find("response>") else {
            break;
        };
        let block = &xml[tag_end..tag_end + close_rel];
        cursor = tag_end + close_rel + 9;

        let Some(href) = extract_xml_tag_text_ns(block, "href") else {
            continue;
        };
        let decoded_href = percent_decode_str(&href);
        let clean_href = decoded_href.trim_end_matches('/');
        if first {
            first = false;
            if clean_href.ends_with(trimmed_dir) || trimmed_dir.is_empty() {
                continue;
            }
        }
        let Some(name_seg) = clean_href.rsplit('/').next() else {
            continue;
        };
        if name_seg.is_empty() || name_seg == "." || name_seg == ".." {
            continue;
        }
        let is_dir = block.contains("collection/>")
            || block.contains("collection />")
            || block.contains(":collection>");
        let size = extract_xml_tag_text_ns(block, "getcontentlength")
            .and_then(|s| s.trim().parse::<u64>().ok());
        let name = name_seg.to_string();
        let (extension, kind) = infer_file_kind(&name, is_dir);
        let full_path = format!("{trimmed_dir}/{name}");
        out.push(FileMetadata {
            is_hidden: name.starts_with('.'),
            name,
            path: full_path,
            extension,
            kind,
            size: if is_dir { None } else { size.or(Some(0)) },
            is_dir,
            is_symlink: false,
            is_locked: false,
            hide_extension: false,
            color_label: ColorLabel::None,
            modified: Some(SystemTime::now()),
            created: Some(SystemTime::now()),
            added: Some(SystemTime::now()),
            permissions: if is_dir { 0o755 } else { 0o644 },
            owner: Some(owner.to_string()),
            group: Some("webdav".to_string()),
        });
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

pub fn webdav_read_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<u8>, VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let cfg = webdav_auth_config(profile, secret, &url);
    run_curl_with_stdin_config(&cfg, &[])
}

pub fn webdav_upload_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    local_path: &Path,
    norm_path: &str,
) -> Result<(), VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let mut cfg = webdav_auth_config(profile, secret, &url);
    cfg.push(format!(
        "upload-file = {}",
        escape_curl_config_val(&local_path.to_string_lossy())
    ));
    let _ = run_curl_with_stdin_config(&cfg, &["-X", "PUT"])?;
    Ok(())
}

pub fn webdav_download_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    local_path: &Path,
) -> Result<(), VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let mut cfg = webdav_auth_config(profile, secret, &url);
    curl_download_atomically(&mut cfg, local_path, &[])
}

pub fn webdav_write_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    data: &[u8],
) -> Result<(), VfsError> {
    let (tmp_path, mut tmp_file) = create_secure_temp_file("webdav_io", "dav-put", ".bin")?;
    tmp_file.write_all(data)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    let res = webdav_upload_file(profile, secret, &tmp_path, norm_path);
    let _ = fs::remove_file(&tmp_path);
    res
}

pub fn webdav_create_dir(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let cfg = webdav_auth_config(profile, secret, &url);
    let _ = run_curl_with_stdin_config(&cfg, &["-X", "MKCOL"])?;
    Ok(())
}

pub fn webdav_remove(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let url = resolve_webdav_url(profile, norm_path)?;
    let cfg = webdav_auth_config(profile, secret, &url);
    let _ = run_curl_with_stdin_config(&cfg, &["-X", "DELETE"])?;
    Ok(())
}

/// Queries WebDAV quota via PROPFIND of the RFC 4918 properties
/// `quota-available-bytes` / `quota-used-bytes` (F-15). Returns `None`
/// when the server does not expose quota information.
pub fn webdav_volume_stats(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Option<VolumeStats> {
    let url = resolve_webdav_url(profile, norm_path).ok()?;
    let mut cfg = webdav_auth_config(profile, secret, &url);
    cfg.push("header = \"Depth: 0\"".to_string());
    cfg.push("header = \"Content-Type: application/xml; charset=utf-8\"".to_string());
    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                <d:propfind xmlns:d=\"DAV:\"><d:prop>\
                <d:quota-available-bytes/><d:quota-used-bytes/>\
                </d:prop></d:propfind>";
    let xml_bytes =
        run_curl_with_stdin_config(&cfg, &["-X", "PROPFIND", "--data-binary", body]).ok()?;
    let xml = String::from_utf8_lossy(&xml_bytes);
    let avail = extract_xml_tag_text_ns(&xml, "quota-available-bytes")?
        .trim()
        .parse::<i64>()
        .ok()?;
    let used = extract_xml_tag_text_ns(&xml, "quota-used-bytes")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0);
    // Negative values mean "unlimited/unknown" per RFC 4918.
    if avail < 0 {
        return None;
    }
    Some(VolumeStats {
        total_bytes: avail.max(0) as u64 + used.max(0) as u64,
        available_bytes: avail as u64,
    })
}

pub fn webdav_move_or_copy(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    from_norm: &str,
    to_norm: &str,
    is_move: bool,
    overwrite: bool,
) -> Result<(), VfsError> {
    let src_url = resolve_webdav_url(profile, from_norm)?;
    let dst_url = resolve_webdav_url(profile, to_norm)?;
    let mut cfg = webdav_auth_config(profile, secret, &src_url);
    cfg.push(format!(
        "header = {}",
        escape_curl_config_val(&format!("Destination: {dst_url}"))
    ));
    // F-6: `Overwrite: T` silently destroyed an existing destination.
    // The default is now `F`; the server rejects with 412 Precondition
    // Failed and the error propagates. Callers that have already resolved
    // a conflict (e.g. deleted the target) may pass `overwrite: true`.
    cfg.push(format!(
        "header = {}",
        escape_curl_config_val(&format!("Overwrite: {}", if overwrite { "T" } else { "F" }))
    ));
    let method = if is_move { "MOVE" } else { "COPY" };
    let _ = run_curl_with_stdin_config(&cfg, &["-X", method])?;
    Ok(())
}

// ============================================================================
// 3. FTP & FTPS (`curl` passive FTP/FTPS with stdin credentials)
// ============================================================================

fn resolve_ftp_url(
    profile: &ConnectionProfile,
    norm_path: &str,
    is_dir: bool,
) -> Result<String, VfsError> {
    let host = profile
        .host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| VfsError::InvalidPath("Missing FTP host".to_string()))?;
    if host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(VfsError::InvalidPath(format!("Invalid FTP host: {host}")));
    }
    let scheme = if profile.protocol == ProtocolType::Ftps {
        "ftps"
    } else {
        "ftp"
    };
    let default_port = if profile.protocol == ProtocolType::Ftps {
        990
    } else {
        21
    };
    let port = profile.port.unwrap_or(default_port);
    let rel = norm_path.trim_matches('/');
    let encoded = uri_encode_s3(rel, false);
    let trailing = if is_dir || rel.is_empty() { "/" } else { "" };
    Ok(format!("{scheme}://{host}:{port}/{encoded}{trailing}"))
}

fn ftp_auth_config(profile: &ConnectionProfile, secret: Option<&str>, url: &str) -> Vec<String> {
    let mut cfg = vec![format!("url = {}", escape_curl_config_val(url))];
    let user = if profile.username.trim().is_empty() {
        "anonymous"
    } else {
        profile.username.trim()
    };
    let user_pass = format!("{user}:{}", secret.unwrap_or(""));
    cfg.push(format!("user = {}", escape_curl_config_val(&user_pass)));
    cfg
}

fn ftp_extra_args(profile: &ConnectionProfile, create_dirs: bool) -> Vec<&'static str> {
    let mut extra = vec!["--ftp-pasv"];
    if create_dirs {
        extra.push("--ftp-create-dirs");
    }
    if profile.protocol == ProtocolType::Ftps {
        extra.push("--ssl-reqd");
    }
    extra
}

pub fn ftp_list_directory(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<FileMetadata>, VfsError> {
    let url = resolve_ftp_url(profile, norm_path, true)?;
    let cfg = ftp_auth_config(profile, secret, &url);
    let extra = ftp_extra_args(profile, false);
    let raw = run_curl_with_stdin_config(&cfg, &extra)?;
    let text = String::from_utf8_lossy(&raw);
    let mut list = parse_ls_aln_output(norm_path, &text, &profile.username, None);
    list.sort_by_key(|a| a.name.to_lowercase());
    Ok(list)
}

pub fn ftp_read_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<u8>, VfsError> {
    let url = resolve_ftp_url(profile, norm_path, false)?;
    let cfg = ftp_auth_config(profile, secret, &url);
    let extra = ftp_extra_args(profile, false);
    run_curl_with_stdin_config(&cfg, &extra)
}

pub fn ftp_upload_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    local_path: &Path,
    norm_path: &str,
) -> Result<(), VfsError> {
    let url = resolve_ftp_url(profile, norm_path, false)?;
    let mut cfg = ftp_auth_config(profile, secret, &url);
    cfg.push(format!(
        "upload-file = {}",
        escape_curl_config_val(&local_path.to_string_lossy())
    ));
    let extra = ftp_extra_args(profile, true);
    let _ = run_curl_with_stdin_config(&cfg, &extra)?;
    Ok(())
}

pub fn ftp_download_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    local_path: &Path,
) -> Result<(), VfsError> {
    let url = resolve_ftp_url(profile, norm_path, false)?;
    let mut cfg = ftp_auth_config(profile, secret, &url);
    let extra = ftp_extra_args(profile, false);
    curl_download_atomically(&mut cfg, local_path, &extra)
}

pub fn ftp_write_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    data: &[u8],
) -> Result<(), VfsError> {
    let (tmp_path, mut tmp_file) = create_secure_temp_file("ftp_io", "ftp-put", ".bin")?;
    tmp_file.write_all(data)?;
    tmp_file.sync_all()?;
    drop(tmp_file);
    let res = ftp_upload_file(profile, secret, &tmp_path, norm_path);
    let _ = fs::remove_file(&tmp_path);
    res
}

pub fn ftp_create_dir(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let url = resolve_ftp_url(profile, "/", true)?;
    let mut cfg = ftp_auth_config(profile, secret, &url);
    let cmd = format!("MKD {}", norm_path.trim_start_matches('/'));
    cfg.push(format!("quote = {}", escape_curl_config_val(&cmd)));
    let extra = ftp_extra_args(profile, false);
    let _ = run_curl_with_stdin_config(&cfg, &extra)?;
    Ok(())
}

pub fn ftp_remove(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    is_dir: bool,
) -> Result<(), VfsError> {
    let url = resolve_ftp_url(profile, "/", true)?;
    let mut cfg = ftp_auth_config(profile, secret, &url);
    let verb = if is_dir { "RMD" } else { "DELE" };
    let cmd = format!("{verb} {}", norm_path.trim_start_matches('/'));
    cfg.push(format!("quote = {}", escape_curl_config_val(&cmd)));
    let extra = ftp_extra_args(profile, false);
    let _ = run_curl_with_stdin_config(&cfg, &extra)?;
    Ok(())
}

pub fn ftp_rename(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    from_norm: &str,
    to_norm: &str,
) -> Result<(), VfsError> {
    let url = resolve_ftp_url(profile, "/", true)?;
    let mut cfg = ftp_auth_config(profile, secret, &url);
    let rnfr = format!("RNFR {}", from_norm.trim_start_matches('/'));
    let rnto = format!("RNTO {}", to_norm.trim_start_matches('/'));
    cfg.push(format!("quote = {}", escape_curl_config_val(&rnfr)));
    cfg.push(format!("quote = {}", escape_curl_config_val(&rnto)));
    let extra = ftp_extra_args(profile, false);
    let _ = run_curl_with_stdin_config(&cfg, &extra)?;
    Ok(())
}

// ============================================================================
// 4. SMB (`smbclient` with 0600 authfile on Unix / UNC path on Windows)
// ============================================================================

fn parse_smb_share_and_subpath(
    profile: &ConnectionProfile,
    norm_path: &str,
) -> Result<(String, String, String), VfsError> {
    let host = profile
        .host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| VfsError::InvalidPath("Missing SMB server host".to_string()))?;
    if host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(VfsError::InvalidPath(format!("Invalid SMB host: {host}")));
    }
    let combined = norm_path.trim_matches('/');
    let base_clean = profile.base_path.trim_matches('/');
    let (share, sub) = if let Some((s, rest)) = combined.split_once('/') {
        (s.to_string(), rest.to_string())
    } else if !combined.is_empty() {
        (combined.to_string(), String::new())
    } else if !base_clean.is_empty() {
        let s = base_clean.split('/').next().unwrap_or(base_clean);
        (s.to_string(), String::new())
    } else {
        return Err(VfsError::InvalidPath(
            "SMB connection requires a share name in Path (e.g. /ShareName)".to_string(),
        ));
    };
    Ok((host.to_string(), share, sub))
}

#[cfg(windows)]
fn windows_connect_unc_path(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    host: &str,
    share: &str,
    sub: &str,
) -> Result<std::path::PathBuf, VfsError> {
    #[repr(C)]
    #[allow(dead_code)]
    struct NetResourceW {
        dw_scope: u32,
        dw_type: u32,
        dw_display_type: u32,
        dw_usage: u32,
        lp_local_name: *const u16,
        lp_remote_name: *const u16,
        lp_comment: *const u16,
        lp_provider: *const u16,
    }
    #[link(name = "mpr")]
    extern "system" {
        fn WNetAddConnection2W(
            lp_net_resource: *const NetResourceW,
            lp_password: *const u16,
            lp_user_name: *const u16,
            dw_flags: u32,
        ) -> u32;
    }

    let unc_share = format!("\\\\{host}\\{share}");
    let wide_unc: Vec<u16> = unc_share.encode_utf16().chain(std::iter::once(0)).collect();
    let user_trimmed = profile.username.trim();
    let wide_user: Vec<u16> = user_trimmed
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let pass_str = secret.unwrap_or("");
    let wide_pass: Vec<u16> = pass_str.encode_utf16().chain(std::iter::once(0)).collect();

    if !user_trimmed.is_empty() || !pass_str.is_empty() {
        let nr = NetResourceW {
            dw_scope: 0,
            dw_type: 1, // RESOURCETYPE_DISK
            dw_display_type: 0,
            dw_usage: 0,
            lp_local_name: std::ptr::null(),
            lp_remote_name: wide_unc.as_ptr(),
            lp_comment: std::ptr::null(),
            lp_provider: std::ptr::null(),
        };
        let u_ptr = if user_trimmed.is_empty() {
            std::ptr::null()
        } else {
            wide_user.as_ptr()
        };
        let p_ptr = if pass_str.is_empty() {
            std::ptr::null()
        } else {
            wide_pass.as_ptr()
        };
        // SAFETY: All UTF-16 buffers are NUL-terminated and live across the FFI call.
        let rc = unsafe { WNetAddConnection2W(&nr, p_ptr, u_ptr, 0) };
        // 0 = NO_ERROR, 85 = ERROR_ALREADY_ASSIGNED, 1219 = ERROR_SESSION_CREDENTIAL_CONFLICT
        if rc != 0 && rc != 85 && rc != 1219 {
            let msg = format!("Windows SMB authentication failed (Win32 error {rc})");
            return Err(VfsError::AuthFailed(msg));
        }
    }

    let mut full = std::path::PathBuf::from(unc_share);
    let clean_sub = sub.trim_matches(['/', '\\']);
    if !clean_sub.is_empty() {
        for seg in clean_sub.split(['/', '\\']) {
            if !seg.is_empty() {
                full.push(seg);
            }
        }
    }
    Ok(full)
}

#[cfg(not(windows))]
fn run_smbclient_cmd(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    share_unc: &str,
    smb_command: &str,
) -> Result<String, VfsError> {
    let (auth_path, mut auth_file) = create_secure_temp_file("smb_auth", "smb", ".auth")?;
    let auth_body = format!(
        "username = {}\npassword = {}\n",
        profile.username.trim().replace('\n', ""),
        secret.unwrap_or("").replace('\n', "")
    );
    auth_file.write_all(auth_body.as_bytes())?;
    auth_file.sync_all()?;
    drop(auth_file);

    let mut cmd = Command::new("smbclient");
    cmd.args([share_unc, "-A"])
        .arg(&auth_path)
        .args(["-c", smb_command]);
    if let Some(port) = profile.port {
        cmd.args(["-p", &port.to_string()]);
    }
    let out_res = cmd.output();
    let _ = fs::remove_file(&auth_path);
    let out = out_res.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            if cfg!(target_os = "macos") {
                // F-28: macOS ships no smbclient; point at the two real
                // options instead of a generic install hint.
                return VfsError::UnsupportedOperation(
                    "SMB browsing needs `smbclient`, which macOS does not ship. Either \
                     mount the share in Finder (Finder ▸ Go ▸ Connect to Server ▸ \
                     smb://server/share) and open it under /Volumes, or install Samba \
                     with `brew install samba`."
                        .to_string(),
                );
            }
            return VfsError::UnsupportedOperation(
                "SMB browsing needs `smbclient`; install the samba-client package.".to_string(),
            );
        }
        VfsError::NetworkError(format!(
            "Failed to run smbclient (ensure samba-client is installed): {e}"
        ))
    })?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(VfsError::NetworkError(if !msg.is_empty() {
            msg
        } else {
            err
        }));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parses `smbclient -c ls` directory output right-to-left so spaces in filenames are preserved.
pub fn parse_smbclient_ls_output(raw: &str, norm_path: &str, owner: &str) -> Vec<FileMetadata> {
    let trimmed_dir = norm_path.trim_end_matches('/');
    let mut list = Vec::new();
    for raw_line in raw.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.ends_with("blocks available") {
            continue;
        }
        // Right-to-left peel: `<name>  [attr]  <size>  <dow> <mon> <day> <hh:mm:ss> <year>`
        let mut rest = trimmed;
        let mut tail_tokens = Vec::with_capacity(6);
        for _ in 0..6 {
            let r = rest.trim_end();
            let Some(pos) = r.rfind(char::is_whitespace) else {
                tail_tokens.clear();
                break;
            };
            tail_tokens.push(&r[pos + 1..]);
            rest = &r[..pos];
        }
        if tail_tokens.len() < 6 {
            continue;
        }
        // tail_tokens[0]=year, [1]=hh:mm:ss, [2]=day, [3]=mon, [4]=dow, [5]=size
        let year_ok =
            tail_tokens[0].len() == 4 && tail_tokens[0].chars().all(|c| c.is_ascii_digit());
        let time_ok = tail_tokens[1].contains(':');
        let Ok(size_val) = tail_tokens[5].parse::<u64>() else {
            continue;
        };
        if !year_ok || !time_ok {
            continue;
        }
        let left_trimmed = rest.trim_end();
        let (name_raw, attr) = if let Some(pos) = left_trimmed.rfind("  ") {
            let cand_attr = left_trimmed[pos..].trim();
            let is_attr = !cand_attr.is_empty()
                && cand_attr.len() <= 8
                && cand_attr
                    .chars()
                    .all(|c| matches!(c, 'D' | 'H' | 'R' | 'A' | 'S' | 'N' | 'C' | 'E' | 'T'));
            if is_attr {
                (left_trimmed[..pos].trim_end(), cand_attr)
            } else {
                (left_trimmed, "")
            }
        } else {
            (left_trimmed, "")
        };
        let name = name_raw.trim().to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let is_dir = attr.contains('D');
        let (extension, kind) = infer_file_kind(&name, is_dir);
        let full_path = format!("{trimmed_dir}/{name}");
        list.push(FileMetadata {
            is_hidden: name.starts_with('.') || attr.contains('H'),
            name,
            path: full_path,
            extension,
            kind,
            size: if is_dir { None } else { Some(size_val) },
            is_dir,
            is_symlink: false,
            is_locked: attr.contains('R'),
            hide_extension: false,
            color_label: ColorLabel::None,
            modified: Some(SystemTime::now()),
            created: Some(SystemTime::now()),
            added: Some(SystemTime::now()),
            permissions: if is_dir { 0o755 } else { 0o644 },
            owner: Some(owner.to_string()),
            group: Some("smb".to_string()),
        });
    }
    list.sort_by_key(|a| a.name.to_lowercase());
    list
}

pub fn smb_list_directory(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<FileMetadata>, VfsError> {
    let (host, share, sub) = parse_smb_share_and_subpath(profile, norm_path)?;
    #[cfg(windows)]
    {
        let unc_dir = windows_connect_unc_path(profile, secret, &host, &share, &sub)?;
        let trimmed_dir = norm_path.trim_end_matches('/');
        let mut list = Vec::new();
        for entry_res in fs::read_dir(&unc_dir)? {
            let entry = entry_res?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let meta = entry.metadata()?;
            let is_dir = meta.is_dir();
            let (extension, kind) = infer_file_kind(&name, is_dir);
            let modified = meta.modified().ok();
            list.push(FileMetadata {
                is_hidden: name.starts_with('.'),
                path: format!("{trimmed_dir}/{name}"),
                name,
                extension,
                kind,
                size: if is_dir { None } else { Some(meta.len()) },
                is_dir,
                is_symlink: meta.file_type().is_symlink(),
                is_locked: meta.permissions().readonly(),
                hide_extension: false,
                color_label: ColorLabel::None,
                modified,
                created: meta.created().ok().or(modified),
                added: modified,
                permissions: if is_dir { 0o755 } else { 0o644 },
                owner: Some(profile.username.clone()),
                group: Some("smb".to_string()),
            });
        }
        list.sort_by_key(|a| a.name.to_lowercase());
        Ok(list)
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let smb_sub = sub.replace('/', "\\").replace('"', "");
        let cmd = if smb_sub.is_empty() {
            "ls".to_string()
        } else {
            format!("cd \"{smb_sub}\"; ls")
        };
        let raw = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(parse_smbclient_ls_output(
            &raw,
            norm_path,
            &profile.username,
        ))
    }
}

pub fn smb_download_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    local_path: &Path,
) -> Result<(), VfsError> {
    let (host, share, sub) = parse_smb_share_and_subpath(profile, norm_path)?;
    #[cfg(windows)]
    {
        let unc_file = windows_connect_unc_path(profile, secret, &host, &share, &sub)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&unc_file, local_path)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let smb_sub = sub.replace('/', "\\").replace('"', "");
        let local_esc = local_path.to_string_lossy().replace('"', "");
        let cmd = format!("get \"{smb_sub}\" \"{local_esc}\"");
        let _ = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(())
    }
}

pub fn smb_upload_file(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    local_path: &Path,
    norm_path: &str,
) -> Result<(), VfsError> {
    let (host, share, sub) = parse_smb_share_and_subpath(profile, norm_path)?;
    #[cfg(windows)]
    {
        let unc_file = windows_connect_unc_path(profile, secret, &host, &share, &sub)?;
        if let Some(parent) = unc_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::copy(local_path, &unc_file)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let smb_sub = sub.replace('/', "\\").replace('"', "");
        let local_esc = local_path.to_string_lossy().replace('"', "");
        let cmd = format!("put \"{local_esc}\" \"{smb_sub}\"");
        let _ = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(())
    }
}

pub fn smb_read_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<Vec<u8>, VfsError> {
    let (tmp_path, _f) = create_secure_temp_file("smb_io", "smb-get", ".bin")?;
    let res = smb_download_file(profile, secret, norm_path, &tmp_path);
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    let bytes = fs::read(&tmp_path)?;
    let _ = fs::remove_file(&tmp_path);
    Ok(bytes)
}

pub fn smb_write_bytes(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    data: &[u8],
) -> Result<(), VfsError> {
    let (tmp_path, mut f) = create_secure_temp_file("smb_io", "smb-put", ".bin")?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    let res = smb_upload_file(profile, secret, &tmp_path, norm_path);
    let _ = fs::remove_file(&tmp_path);
    res
}

pub fn smb_create_dir(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
) -> Result<(), VfsError> {
    let (host, share, sub) = parse_smb_share_and_subpath(profile, norm_path)?;
    #[cfg(windows)]
    {
        let unc_dir = windows_connect_unc_path(profile, secret, &host, &share, &sub)?;
        fs::create_dir_all(&unc_dir)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let smb_sub = sub.replace('/', "\\").replace('"', "");
        let cmd = format!("mkdir \"{smb_sub}\"");
        let _ = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(())
    }
}

pub fn smb_remove(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    norm_path: &str,
    recursive: bool,
) -> Result<(), VfsError> {
    let (host, share, sub) = parse_smb_share_and_subpath(profile, norm_path)?;
    #[cfg(windows)]
    {
        let unc_target = windows_connect_unc_path(profile, secret, &host, &share, &sub)?;
        if unc_target.is_dir() {
            if recursive {
                fs::remove_dir_all(&unc_target)?;
            } else {
                fs::remove_dir(&unc_target)?;
            }
        } else {
            fs::remove_file(&unc_target)?;
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let smb_sub = sub.replace('/', "\\").replace('"', "");
        let verb = if recursive { "deltree" } else { "rm" };
        let cmd = format!("{verb} \"{smb_sub}\"");
        let _ = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(())
    }
}

pub fn smb_rename(
    profile: &ConnectionProfile,
    secret: Option<&str>,
    from_norm: &str,
    to_norm: &str,
) -> Result<(), VfsError> {
    let (host, share, sub_from) = parse_smb_share_and_subpath(profile, from_norm)?;
    let (_, _, sub_to) = parse_smb_share_and_subpath(profile, to_norm)?;
    #[cfg(windows)]
    {
        let unc_from = windows_connect_unc_path(profile, secret, &host, &share, &sub_from)?;
        let unc_to = windows_connect_unc_path(profile, secret, &host, &share, &sub_to)?;
        fs::rename(&unc_from, &unc_to)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let share_unc = format!("//{host}/{share}");
        let s1 = sub_from.replace('/', "\\").replace('"', "");
        let s2 = sub_to.replace('/', "\\").replace('"', "");
        let cmd = format!("rename \"{s1}\" \"{s2}\"");
        let _ = run_smbclient_cmd(profile, secret, &share_unc, &cmd)?;
        Ok(())
    }
}

// ============================================================================
// Shared XML & URI Helpers
// ============================================================================

fn extract_xml_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    Some(xml_unescape(&xml[start..start + end]))
}

fn extract_xml_tag_text_ns(xml: &str, local_tag: &str) -> Option<String> {
    for prefix in ["d:", "D:", "lp1:", ""] {
        let tag = format!("{prefix}{local_tag}");
        if let Some(val) = extract_xml_tag_text(xml, &tag) {
            return Some(val);
        }
    }
    None
}

/// Decodes XML entities in a single left-to-right pass (F-20): the previous
/// chained `String::replace` calls double-decoded, so `&amp;lt;` wrongly
/// became `<` instead of the literal `&lt;`. Also accepts numeric character
/// references (`&#39;`, `&#x27;`).
fn xml_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        let tail = &rest[idx + 1..];
        if let Some(code) = tail.strip_prefix('#') {
            let (digits, radix) = if let Some(hex) = code.strip_prefix('x') {
                (hex, 16u32)
            } else {
                (code, 10u32)
            };
            let semi = digits.find(';').unwrap_or(digits.len());
            let terminated = digits.as_bytes().get(semi) == Some(&b';');
            let num = u32::from_str_radix(&digits[..semi], radix)
                .ok()
                .filter(|_| !digits[..semi].is_empty());
            match (terminated, num.and_then(char::from_u32)) {
                (true, Some(c)) => {
                    out.push(c);
                    // consumed = '#' [+ 'x'] + digits + ';'
                    let consumed = tail.len() - digits[semi..].len();
                    rest = &tail[consumed + 1..];
                    continue;
                }
                _ => {
                    out.push('&');
                    rest = tail;
                    continue;
                }
            }
        }
        let entity = [
            ("amp", '&'),
            ("lt", '<'),
            ("gt", '>'),
            ("quot", '"'),
            ("apos", '\''),
        ]
        .into_iter()
        .find(|(name, _)| tail.starts_with(*name) && tail[name.len()..].starts_with(';'));
        match entity {
            Some((name, c)) => {
                out.push(c);
                rest = &tail[name.len() + 1..];
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_known_answer() {
        // openssl dgst -sha256 -hmac key
        let mac = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex_encode(&mac),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn xml_unescape_never_double_decodes() {
        assert_eq!(xml_unescape("&amp;lt;"), "&lt;");
        assert_eq!(xml_unescape("&amp;amp;"), "&amp;");
        assert_eq!(xml_unescape("&lt;script&gt;"), "<script>");
        assert_eq!(xml_unescape("a &amp; b &amp; c"), "a & b & c");
        assert_eq!(xml_unescape("Tom&apos;s &quot;x&quot;"), "Tom's \"x\"");
        assert_eq!(xml_unescape("plain text"), "plain text");
        assert_eq!(xml_unescape("100% & not-an-entity"), "100% & not-an-entity");
    }

    #[test]
    fn xml_unescape_numeric_references() {
        assert_eq!(xml_unescape("&#39;quoted&#39;"), "'quoted'");
        assert_eq!(xml_unescape("&#x41;&#66;"), "AB");
        assert_eq!(xml_unescape("&#38;lt;"), "&lt;");
        assert_eq!(xml_unescape("&#;broken"), "&#;broken");
        assert_eq!(xml_unescape("&#xZZ;"), "&#xZZ;");
    }

    /// Serializes tests that shadow the real `curl` via `PATH`.
    fn curl_path_lock() -> std::sync::MutexGuard<'static, ()> {
        static PATH_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        PATH_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Installs a fake `curl` binary whose behavior is defined by `body`
    /// (a POSIX snippet receiving the curl config on stdin).
    fn install_fake_curl(body: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("curl");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut combined = std::ffi::OsString::from(dir.path());
        if let Some(old) = std::env::var_os("PATH") {
            combined.push(":");
            combined.push(&old);
        }
        std::env::set_var("PATH", combined);
        dir
    }

    fn s3_profile() -> ConnectionProfile {
        let mut profile = ConnectionProfile::new_sftp_default("s3-1", "Test Bucket");
        profile.protocol = ProtocolType::S3;
        profile.endpoint = Some("s3.example.com".to_string());
        profile.bucket = Some("mybucket".to_string());
        profile.username = "AKIAEXAMPLE".to_string();
        profile
    }

    #[test]
    fn s3_list_directory_follows_continuation_tokens() {
        let _guard = curl_path_lock();
        let dir = install_fake_curl(
            r#"cfg=$(cat)
case "$cfg" in
  *continuation-token=*)
    printf '<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>docs/b.txt</Key><Size>2</Size></Contents></ListBucketResult>'
    ;;
  *)
    printf '<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t/1+2=</NextContinuationToken><Contents><Key>docs/a.txt</Key><Size>1</Size></Contents></ListBucketResult>'
    ;;
esac"#,
        );
        let entries = s3_list_directory(&s3_profile(), Some("secret"), "/docs").unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.txt"], "both pages must be listed");
        drop(dir);
    }

    #[test]
    fn s3_remove_tree_deletes_every_child_key_and_marker() {
        let _guard = curl_path_lock();
        let log_dir = tempfile::tempdir().unwrap();
        let log = log_dir.path().join("deleted.log");
        std::env::set_var("MANIFOLD_DELETE_LOG", &log);
        let dir = install_fake_curl(
            r#"cfg=$(cat)
case "$cfg" in
  *"list-type=2"*)
    printf '<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>docs/a.txt</Key></Contents><Contents><Key>docs/sub/c.txt</Key></Contents></ListBucketResult>'
    ;;
  *)
    printf '%s\n' "$cfg" | grep '^url = ' >> "$MANIFOLD_DELETE_LOG"
    ;;
esac"#,
        );
        s3_remove_tree(&s3_profile(), Some("secret"), "/docs").unwrap();
        let deleted = std::fs::read_to_string(&log).unwrap();
        assert!(deleted.contains("docs/a.txt"), "child a missing: {deleted}");
        assert!(
            deleted.contains("docs/sub/c.txt"),
            "grandchild missing: {deleted}"
        );
        assert!(deleted.contains("docs/"), "marker missing: {deleted}");
        std::env::remove_var("MANIFOLD_DELETE_LOG");
        drop(dir);
    }

    #[test]
    fn azure_blob_is_rejected_instead_of_sigv4_misrouting() {
        // F-31: Azure cannot speak AWS SigV4; it must fail honestly.
        let mut profile = ConnectionProfile::new_sftp_default("az-1", "Azure");
        profile.protocol = ProtocolType::AzureBlob;
        profile.bucket = Some("container".to_string());
        let err = s3_list_directory(&profile, Some("k"), "/")
            .expect_err("Azure must be rejected up front");
        assert!(
            matches!(err, VfsError::UnsupportedOperation(_)),
            "got: {err}"
        );
    }

    #[test]
    fn gcs_defaults_to_interoperability_endpoint() {
        let _guard = curl_path_lock();
        let log_dir = tempfile::tempdir().unwrap();
        let log = log_dir.path().join("url.log");
        std::env::set_var("MANIFOLD_URL_LOG", &log);
        let dir = install_fake_curl(
            r#"cfg=$(cat)
printf '%s\n' "$cfg" | grep '^url = ' >> "$MANIFOLD_URL_LOG"
printf '<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>'"#,
        );
        let mut profile = ConnectionProfile::new_sftp_default("gcs-1", "Google Cloud");
        profile.protocol = ProtocolType::Gcs;
        profile.bucket = Some("my-bucket".to_string());
        profile.host = None;
        profile.endpoint = None;
        s3_list_directory(&profile, Some("goog_key"), "/").unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains("storage.googleapis.com/my-bucket"),
            "GCS must route to the interoperability endpoint, got: {logged}"
        );
        std::env::remove_var("MANIFOLD_URL_LOG");
        drop(dir);
    }

    #[test]
    fn webdav_quota_propfind_reports_real_capacity() {
        let _guard = curl_path_lock();
        let dir = install_fake_curl(
            r#"printf '<D:multistatus xmlns:D="DAV:"><D:response><D:propstat><D:prop><D:quota-available-bytes>300</D:quota-available-bytes><D:quota-used-bytes>100</D:quota-used-bytes></D:prop></D:propstat></D:response></D:multistatus>'"#,
        );
        let stats = webdav_volume_stats(&s3_profile(), Some("s"), "/").expect("quota reported");
        assert_eq!(stats.available_bytes, 300);
        assert_eq!(stats.total_bytes, 400);
        drop(dir);

        // Unlimited/unknown quota (-1/-2) must yield None, not fake numbers.
        let dir = install_fake_curl(
            r#"printf '<D:multistatus xmlns:D="DAV:"><D:response><D:propstat><D:prop><D:quota-available-bytes>-3</D:quota-available-bytes><D:quota-used-bytes>100</D:quota-used-bytes></D:prop></D:propstat></D:response></D:multistatus>'"#,
        );
        assert!(webdav_volume_stats(&s3_profile(), Some("s"), "/").is_none());
        drop(dir);

        // No quota properties at all: None.
        let dir = install_fake_curl(
            r#"printf '<D:multistatus xmlns:D="DAV:"><D:response><D:propstat><D:prop></D:prop></D:propstat></D:response></D:multistatus>'"#,
        );
        assert!(webdav_volume_stats(&s3_profile(), Some("s"), "/").is_none());
        drop(dir);
    }

    #[test]
    fn webdav_download_replaces_target_only_on_success() {
        let _guard = curl_path_lock();
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("out.bin");
        std::fs::write(&target, b"ORIGINAL").unwrap();

        // Failing transfer (HTTP 4xx with --fail-with-body): the existing
        // file must survive untouched (F-3).
        let dir = install_fake_curl(
            r#"cfg=$(cat)
out=$(printf '%s\n' "$cfg" | sed -n 's/^output = //p' | tr -d '"')
printf 'PARTIAL' > "$out"
exit 22"#,
        );
        let err = webdav_download_file(&s3_profile(), Some("s"), "/remote.bin", &target)
            .expect_err("failed transfer must error");
        let _ = err;
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL");
        drop(dir);

        // Successful transfer: content replaced atomically, no leftovers.
        let dir = install_fake_curl(
            r#"cfg=$(cat)
out=$(printf '%s\n' "$cfg" | sed -n 's/^output = //p' | tr -d '"')
printf 'NEW-CONTENT' > "$out"
exit 0"#,
        );
        webdav_download_file(&s3_profile(), Some("s"), "/remote.bin", &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW-CONTENT");
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".manifold-dl"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp download leftovers: {leftovers:?}"
        );
        drop(dir);
    }
}
