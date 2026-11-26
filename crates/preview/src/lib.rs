//! Inspector & Quick Look Preview Engine (`manifold-preview`) for Project Manifold.
//!
//! Models the 3-tab Right Inspector Drawer (`ⓘ Info | ⇅ Activities | ⚠ Logs`) shown in
//! `doc/image1.png` and `doc/image2.png`, including syntax-highlighted code lines, image
//! pan/zoom, PDF/media descriptors, Hex View formatting, and the `General` and `Permissions`
//! collapsible sections.

use std::path::Path;

use manifold_vfs::{FileMetadata, PermissionsMatrix};
use serde::{Deserialize, Serialize};

/// Top 3-tab switcher in the Right Inspector Drawer (`doc/image1.png` & `doc/image2.png`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InspectorTab {
    /// `ⓘ` Info & Preview Inspector.
    #[default]
    Info,
    /// `⇅` Active & Queued File Transfers (`Activities`).
    Activities,
    /// `⚠` Diagnostics, Warnings & Error Logs.
    Logs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighlightedLine {
    pub line_number: usize,
    pub language: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PreviewPayload {
    TextCode {
        language: String,
        lines: Vec<HighlightedLine>,
    },
    Image {
        format: String,
        /// Real pixel dimensions parsed from the file header; `None` when
        /// the sample did not contain them (F-16, no invented 1920×1080).
        width: Option<u32>,
        height: Option<u32>,
        zoom: f32,
        pan_x: f32,
        pan_y: f32,
    },
    AudioVideo {
        media_kind: String,
        /// Duration in seconds if reliably known; `None` instead of a
        /// fabricated 120 s default (F-16).
        duration_secs: Option<u64>,
        is_playing: bool,
    },
    Pdf {
        /// Page count parsed from the (sampled) PDF structure; `None`
        /// instead of a fabricated 1 (F-16).
        page_count: Option<u32>,
        current_page: u32,
    },
    HexDump {
        formatted_rows: Vec<String>,
    },
    Folder {
        item_count: usize,
        total_bytes: Option<u64>,
    },
}

/// Parses image pixel dimensions from a header sample for PNG, JPEG, GIF
/// and WebP (F-16). Returns `None` for unknown or truncated formats.
pub fn parse_image_dimensions(sample: &[u8]) -> Option<(u32, u32)> {
    // PNG: 8-byte signature, IHDR at offset 12, width/height BE at 16/20.
    if sample.len() >= 24 && sample[0..8] == *b"\x89PNG\r\n\x1a\n" && sample[12..16] == *b"IHDR" {
        let w = u32::from_be_bytes([sample[16], sample[17], sample[18], sample[19]]);
        let h = u32::from_be_bytes([sample[20], sample[21], sample[22], sample[23]]);
        if w > 0 && h > 0 {
            return Some((w, h));
        }
        return None;
    }
    // GIF: "GIF87a"/"GIF89a", logical screen width/height LE at 6/8.
    if sample.len() >= 10 && sample[0..4] == *b"GIF8" {
        let w = u16::from_le_bytes([sample[6], sample[7]]) as u32;
        let h = u16::from_le_bytes([sample[8], sample[9]]) as u32;
        if w > 0 && h > 0 {
            return Some((w, h));
        }
        return None;
    }
    // JPEG: SOI followed by SOFn segments (C0..CF except C4/D8/CC).
    if sample.len() >= 4 && sample[0..2] == *b"\xFF\xD8" {
        let mut i = 2usize;
        while i + 8 < sample.len() {
            if sample[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = sample[i + 1];
            if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
                let h = u16::from_be_bytes([sample[i + 5], sample[i + 6]]) as u32;
                let w = u16::from_be_bytes([sample[i + 7], sample[i + 8]]) as u32;
                if w > 0 && h > 0 {
                    return Some((w, h));
                }
            }
            // Skip this segment via its 16-bit length.
            let len = u16::from_be_bytes([sample[i + 2], sample[i + 3]]) as usize;
            i += 2 + len.max(2);
        }
        return None;
    }
    // WebP: RIFF....WEBP with VP8/VP8L/VP8X chunk.
    if sample.len() >= 30 && sample[0..4] == *b"RIFF" && sample[8..12] == *b"WEBP" {
        match &sample[12..16] {
            b"VP8 " => {
                // Frame data starts at 23; dimensions at 26/29 (LE 14-bit).
                let w = (u16::from_le_bytes([sample[26], sample[27]]) & 0x3FFF) as u32;
                let h = (u16::from_le_bytes([sample[28], sample[29]]) & 0x3FFF) as u32;
                if w > 0 && h > 0 {
                    return Some((w, h));
                }
            }
            b"VP8L" => {
                let bits = u32::from_le_bytes([sample[21], sample[22], sample[23], sample[24]]);
                let w = (bits & 0x3FFF) + 1;
                let h = ((bits >> 14) & 0x3FFF) + 1;
                return Some((w, h));
            }
            b"VP8X" => {
                let w =
                    (sample[24] as u32 | (sample[25] as u32) << 8 | (sample[26] as u32) << 16) + 1;
                let h =
                    (sample[27] as u32 | (sample[28] as u32) << 8 | (sample[29] as u32) << 16) + 1;
                return Some((w, h));
            }
            _ => {}
        }
    }
    None
}

/// Counts PDF pages from a sampled byte range (F-16): prefers the
/// `/Count` value of the page tree; falls back to counting
/// `/Type /Page` (not `/Pages`) occurrences. `None` when the sample does
/// not contain enough structure to tell — never a fabricated 1.
pub fn parse_pdf_page_count(sample: &[u8]) -> Option<u32> {
    if !sample.starts_with(b"%PDF") {
        return None;
    }
    let text = String::from_utf8_lossy(sample);
    if let Some(rest) = text.split("/Count").nth(1) {
        let digits: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<u32>() {
            if n > 0 {
                return Some(n);
            }
        }
    }
    let mut count = 0u32;
    let mut idx = 0usize;
    while let Some(pos) = text[idx..].find("/Type") {
        let at = idx + pos + 5;
        let tail = text[at..].trim_start();
        if let Some(after) = tail.strip_prefix("/Page") {
            if !after.starts_with('s') {
                count += 1;
            }
        }
        idx = at;
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

/// `General` collapsible section in the Right Inspector (`doc/image1.png` & `doc/image2.png`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralInspectorSection {
    pub expanded: bool,
    pub path: String,
    pub size: String,
    pub modified: String,
    pub created: String,
    pub added: String,
    pub extension: String,
    pub hide_extension: bool,
}

/// `Permissions` collapsible section in the Right Inspector (`doc/image1.png` & `doc/image2.png`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionsInspectorSection {
    pub expanded: bool,
    pub matrix: PermissionsMatrix,
    pub octal_symbolic: String,
    pub octal_code: String,
    pub owner: String,
    pub group: String,
    pub locked: bool,
}

/// Complete view-model for the `ⓘ` Info tab of the Right Inspector Drawer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileInspectorViewModel {
    pub title: String,
    pub subtitle: String,
    pub preview: PreviewPayload,
    pub general: GeneralInspectorSection,
    pub permissions: PermissionsInspectorSection,
}

impl FileInspectorViewModel {
    /// Builds the exact Inspector view-model shown in `doc/image1.png` & `doc/image2.png`
    /// from a [`FileMetadata`] entry and optional sample bytes.
    pub fn from_metadata(
        meta: &FileMetadata,
        formatted_timestamp: &str,
        sample_bytes: Option<&[u8]>,
    ) -> Self {
        let size_str = meta.formatted_size();
        let subtitle = format!("{} - {}", meta.kind, size_str);
        let parent_dir = Path::new(&meta.path)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string();

        let matrix = meta.permissions_matrix();
        let preview = Self::build_preview_payload(meta, sample_bytes);
        let owner = meta.owner.clone().unwrap_or_else(|| "—".to_string());
        let group = meta.group.clone().unwrap_or_else(|| "—".to_string());

        Self {
            title: meta.display_name(),
            subtitle,
            preview,
            general: GeneralInspectorSection {
                expanded: true,
                path: parent_dir,
                size: size_str,
                modified: formatted_timestamp.to_string(),
                created: formatted_timestamp.to_string(),
                added: formatted_timestamp.to_string(),
                extension: meta.extension.clone().unwrap_or_default(),
                hide_extension: meta.hide_extension,
            },
            permissions: PermissionsInspectorSection {
                expanded: true,
                matrix,
                octal_symbolic: matrix.to_symbolic_string(),
                octal_code: matrix.to_octal_string(),
                owner,
                group,
                locked: meta.is_locked,
            },
        }
    }

    fn build_preview_payload(meta: &FileMetadata, sample_bytes: Option<&[u8]>) -> PreviewPayload {
        if meta.is_dir {
            return PreviewPayload::Folder {
                item_count: 0,
                total_bytes: meta.size,
            };
        }
        match meta.extension.as_deref() {
            Some("jpg" | "jpeg" | "png" | "svg" | "webp" | "avif") => {
                let dims = sample_bytes.and_then(parse_image_dimensions);
                let (width, height) = match dims {
                    Some((w, h)) => (Some(w), Some(h)),
                    None => (None, None),
                };
                PreviewPayload::Image {
                    format: meta.kind.clone(),
                    width,
                    height,
                    zoom: 1.0,
                    pan_x: 0.0,
                    pan_y: 0.0,
                }
            }
            Some("pdf") => PreviewPayload::Pdf {
                page_count: sample_bytes.and_then(parse_pdf_page_count),
                current_page: 1,
            },
            Some("mp3" | "wav" | "flac" | "ogg" | "mp4" | "mkv" | "mov" | "webm") => {
                PreviewPayload::AudioVideo {
                    media_kind: meta.kind.clone(),
                    // F-16: no reliable duration from a small sample; the
                    // GUI's media section parses real headers itself.
                    duration_secs: None,
                    is_playing: false,
                }
            }
            Some("rs" | "php" | "toml" | "html" | "txt" | "md" | "json") => {
                let utf8 = sample_bytes.and_then(|b| std::str::from_utf8(b).ok());
                let text = utf8.unwrap_or("");
                let lang = meta.kind.clone();
                let lines = text
                    .lines()
                    .enumerate()
                    .map(|(idx, line)| HighlightedLine {
                        line_number: idx + 1,
                        language: lang.clone(),
                        text: line.to_string(),
                    })
                    .collect();
                PreviewPayload::TextCode {
                    language: lang,
                    lines,
                }
            }
            _ => {
                let bytes = sample_bytes.unwrap_or(&[]);
                PreviewPayload::HexDump {
                    formatted_rows: format_hex_dump(bytes, 16),
                }
            }
        }
    }
}

/// Formats binary data into standard 16-byte Hex + ASCII inspector rows (`Section 2.1.5` of `BRIEF.md`).
pub fn format_hex_dump(bytes: &[u8], max_rows: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for (row_idx, chunk) in bytes.chunks(16).take(max_rows).enumerate() {
        let offset = row_idx * 16;
        let mut hex_part = String::with_capacity(48);
        let mut ascii_part = String::with_capacity(16);
        for &b in chunk {
            hex_part.push_str(&format!("{b:02x} "));
            let ch = if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            };
            ascii_part.push(ch);
        }
        for _ in chunk.len()..16 {
            hex_part.push_str("   ");
        }
        rows.push(format!("{offset:08x}: {hex_part}| {ascii_part}"));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifold_vfs::ColorLabel;

    #[test]
    fn test_inspector_view_model_matches_waterfall_jpg_in_image1_and_image2() {
        let meta = FileMetadata {
            name: "Waterfall.jpg".to_string(),
            path: "/Users/johnappleseed/Photos/Waterfall.jpg".to_string(),
            extension: Some("jpg".to_string()),
            kind: "JPEG image".to_string(),
            size: Some(9_751_756), // ~9,3 MB
            is_dir: false,
            is_symlink: false,
            is_hidden: false,
            is_locked: false,
            hide_extension: false,
            color_label: ColorLabel::None,
            modified: None,
            created: None,
            added: None,
            permissions: 0o644,
            owner: Some("johnappleseed".to_string()),
            group: Some("staff".to_string()),
        };

        let vm = FileInspectorViewModel::from_metadata(&meta, "2023.08.31, 14:57", None);
        assert_eq!(vm.title, "Waterfall.jpg");
        assert_eq!(vm.subtitle, "JPEG image - 9,3 MB");
        assert_eq!(vm.general.path, "/Users/johnappleseed/Photos");
        assert_eq!(vm.general.size, "9,3 MB");
        assert_eq!(vm.general.extension, "jpg");
        assert!(!vm.general.hide_extension);
        assert_eq!(vm.permissions.octal_symbolic, "rw-r--r--");
        assert_eq!(vm.permissions.octal_code, "644");
        assert_eq!(vm.permissions.owner, "johnappleseed");
        assert_eq!(vm.permissions.group, "staff");
        assert!(!vm.permissions.locked);
    }

    #[test]
    fn test_hex_dump_formatter() {
        let data = b"Manifold VFS Hex Inspector";
        let dump = format_hex_dump(data, 4);
        assert_eq!(dump.len(), 2);
        assert!(dump[0].starts_with("00000000: 4d 61 6e 69 66 6f 6c 64"));
        assert!(dump[0].ends_with("| Manifold VFS Hex"));
    }

    fn jpg_meta() -> FileMetadata {
        FileMetadata {
            name: "x.jpg".to_string(),
            path: "/x.jpg".to_string(),
            extension: Some("jpg".to_string()),
            kind: "JPEG image".to_string(),
            size: Some(10),
            is_dir: false,
            is_symlink: false,
            is_hidden: false,
            is_locked: false,
            hide_extension: false,
            color_label: manifold_vfs::ColorLabel::None,
            modified: None,
            created: None,
            added: None,
            permissions: 0o644,
            owner: None,
            group: None,
        }
    }

    #[test]
    fn image_dimensions_come_from_real_headers() {
        // PNG 123×77
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(b"\x00\x00\x00\rIHDR");
        png.extend_from_slice(&123u32.to_be_bytes());
        png.extend_from_slice(&77u32.to_be_bytes());
        assert_eq!(parse_image_dimensions(&png), Some((123, 77)));

        // GIF 10×20
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&10u16.to_le_bytes());
        gif.extend_from_slice(&20u16.to_le_bytes());
        assert_eq!(parse_image_dimensions(&gif), Some((10, 20)));

        // JPEG SOF0 320×240
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
        jpg.extend_from_slice(&240u16.to_be_bytes());
        jpg.extend_from_slice(&320u16.to_be_bytes());
        assert_eq!(parse_image_dimensions(&jpg), Some((320, 240)));

        // Garbage stays unknown instead of inventing 1920×1080 (F-16).
        assert_eq!(parse_image_dimensions(b"not an image"), None);
    }

    #[test]
    fn pdf_page_count_is_parsed_or_none() {
        let pdf = b"%PDF-1.7\n1 0 obj << /Type /Pages /Count 7 /Kids [2 0 R] >> endobj\n";
        assert_eq!(parse_pdf_page_count(pdf), Some(7));
        let pdf2 = b"%PDF-1.4 << /Type /Page >> x /Type /Pages y /Type /Page";
        assert_eq!(parse_pdf_page_count(pdf2), Some(2));
        assert_eq!(parse_pdf_page_count(b"nope"), None);
        assert_eq!(parse_pdf_page_count(b"%PDF-1.4 truncated"), None);
    }

    #[test]
    fn missing_sample_yields_unknown_not_fabricated_values() {
        let vm = FileInspectorViewModel::from_metadata(&jpg_meta(), "ts", None);
        match vm.preview {
            PreviewPayload::Image { width, height, .. } => {
                assert!(width.is_none() && height.is_none(), "F-16 invented dims");
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
