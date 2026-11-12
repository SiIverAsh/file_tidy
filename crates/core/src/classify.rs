//! Side-effect-free classification from names, approved magic evidence and time.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Document,
    Image,
    Video,
    Audio,
    Archive,
    Code,
    Installer,
    #[default]
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Image => "image",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Archive => "archive",
            Self::Code => "code",
            Self::Installer => "installer",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeEvidence {
    Extension,
    Magic,
    Agreement,
    Conflict,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Classification {
    pub category: Category,
    pub extension: Option<String>,
    pub mime: Option<String>,
    pub evidence: TypeEvidence,
    /// Modification month in UTC, not last-use time or a local-time guess.
    pub year_month: Option<String>,
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid TOML classification rules: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid classification rules: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct Rules {
    extensions: BTreeMap<String, Category>,
    mime_types: BTreeMap<String, Category>,
    mime_prefixes: BTreeMap<String, Category>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesDocument {
    schema_version: u32,
    rules: Vec<RuleDefinition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDefinition {
    category: Category,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    mime_types: Vec<String>,
    #[serde(default)]
    mime_prefixes: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        // Built-ins are constructed directly so production has no expect/panic
        // path for parsing a bundled document. A test proves TOML equivalence.
        let mut rules = Self::empty();
        for (category, extensions, mime_types, mime_prefixes) in DEFAULT_RULES {
            for extension in *extensions {
                rules.extensions.insert((*extension).to_owned(), *category);
            }
            for mime in *mime_types {
                rules.mime_types.insert((*mime).to_owned(), *category);
            }
            for prefix in *mime_prefixes {
                rules.mime_prefixes.insert((*prefix).to_owned(), *category);
            }
        }
        rules
    }
}

impl Rules {
    fn empty() -> Self {
        Self {
            extensions: BTreeMap::new(),
            mime_types: BTreeMap::new(),
            mime_prefixes: BTreeMap::new(),
        }
    }

    /// Read and validate a caller-provided TOML string. No filesystem access.
    /// Custom rules replace the built-in classification mappings, not policy.
    pub fn from_toml(source: &str) -> Result<Self, RuleError> {
        if source.len() > 1024 * 1024 {
            return Err(RuleError::Invalid("rule document exceeds 1 MiB".to_owned()));
        }
        let document: RulesDocument = toml::from_str(source)?;
        if document.schema_version != 1 {
            return Err(RuleError::Invalid("schema_version must be 1".to_owned()));
        }
        if document.rules.len() > 256 {
            return Err(RuleError::Invalid(
                "at most 256 classification rules are allowed".to_owned(),
            ));
        }
        let mut rules = Self::empty();
        for definition in document.rules {
            if definition.extensions.is_empty()
                && definition.mime_types.is_empty()
                && definition.mime_prefixes.is_empty()
            {
                return Err(RuleError::Invalid("empty classification rule".to_owned()));
            }
            for extension in definition.extensions {
                if extension.is_empty()
                    || extension.len() > 64
                    || extension.starts_with('.')
                    || extension.ends_with('.')
                    || extension.contains("..")
                    || !extension.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                    })
                {
                    return Err(RuleError::Invalid(
                        "extensions must be simple suffixes without paths or wildcards".to_owned(),
                    ));
                }
                insert_unique(
                    &mut rules.extensions,
                    extension.to_ascii_lowercase(),
                    definition.category,
                    "extension",
                )?;
            }
            for mime in definition.mime_types {
                if !valid_mime(&mime, false) {
                    return Err(RuleError::Invalid("invalid exact MIME type".to_owned()));
                }
                insert_unique(
                    &mut rules.mime_types,
                    mime.to_ascii_lowercase(),
                    definition.category,
                    "MIME type",
                )?;
            }
            for prefix in definition.mime_prefixes {
                if !valid_mime(&prefix, true) {
                    return Err(RuleError::Invalid(
                        "MIME prefixes must end in / and contain a simple type name".to_owned(),
                    ));
                }
                insert_unique(
                    &mut rules.mime_prefixes,
                    prefix.to_ascii_lowercase(),
                    definition.category,
                    "MIME prefix",
                )?;
            }
        }
        Ok(rules)
    }

    pub fn classify(
        &self,
        path: &Path,
        mime: Option<&str>,
        modified: Option<SystemTime>,
    ) -> Classification {
        let extension = self.extension(path);
        let extension_category = extension
            .as_ref()
            .and_then(|extension| self.extensions.get(extension))
            .copied();
        let normalized_mime = mime.map(str::to_ascii_lowercase);
        let magic_category = normalized_mime.as_deref().map(|mime| {
            self.mime_types
                .get(mime)
                .copied()
                .or_else(|| {
                    self.mime_prefixes.iter().find_map(|(prefix, category)| {
                        mime.starts_with(prefix).then_some(*category)
                    })
                })
                .unwrap_or(Category::Other)
        });
        let (category, evidence) = match (extension_category, magic_category) {
            (Some(extension), Some(magic)) if extension == magic => {
                (magic, TypeEvidence::Agreement)
            }
            (Some(_), Some(magic)) => (magic, TypeEvidence::Conflict),
            (Some(extension), None) => (extension, TypeEvidence::Extension),
            (None, Some(magic)) => (magic, TypeEvidence::Magic),
            (None, None) => (Category::Other, TypeEvidence::Unknown),
        };
        Classification {
            category,
            extension,
            mime: normalized_mime,
            evidence,
            year_month: modified.and_then(year_month),
        }
    }

    fn extension(&self, path: &Path) -> Option<String> {
        let name = path.file_name()?.as_encoded_bytes();
        // Match the longest known compound suffix while keeping the original
        // OsString untouched. A non-UTF-8 stem still has a valid ASCII suffix.
        for (index, byte) in name.iter().enumerate() {
            if *byte != b'.' || index == 0 {
                continue;
            }
            if let Ok(suffix) = std::str::from_utf8(&name[index + 1..]) {
                let suffix = suffix.to_ascii_lowercase();
                if self.extensions.contains_key(&suffix) {
                    return Some(suffix);
                }
            }
        }
        path.extension()?.to_str().map(str::to_ascii_lowercase)
    }
}

fn insert_unique(
    map: &mut BTreeMap<String, Category>,
    key: String,
    category: Category,
    field: &str,
) -> Result<(), RuleError> {
    if map.insert(key, category).is_some() {
        return Err(RuleError::Invalid(format!("duplicate {field} mapping")));
    }
    Ok(())
}

fn valid_mime(value: &str, prefix: bool) -> bool {
    if value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+')
        })
    {
        return false;
    }
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.contains('/')
        && if prefix {
            subtype.is_empty()
        } else {
            !subtype.is_empty()
        }
}

fn year_month(time: SystemTime) -> Option<String> {
    let nanos = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
        Err(error) => i128::try_from(error.duration().as_nanos())
            .ok()?
            .checked_neg()?,
    };
    let date = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    Some(format!("{:04}-{:02}", date.year(), u8::from(date.month())))
}

type DefaultRule = (
    Category,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
);

const DEFAULT_RULES: &[DefaultRule] = &[
    (
        Category::Document,
        &[
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf",
            "epub",
        ],
        &[
            "application/pdf",
            "application/rtf",
            "application/epub+zip",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "text/plain",
        ],
        &[],
    ),
    (
        Category::Image,
        &[
            "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "heic", "heif", "avif",
            "svg", "ico", "raw",
        ],
        &[],
        &["image/"],
    ),
    (
        Category::Video,
        &[
            "mp4", "mkv", "mov", "avi", "webm", "m4v", "mpeg", "mpg", "wmv",
        ],
        &[],
        &["video/"],
    ),
    (
        Category::Audio,
        &[
            "mp3", "flac", "wav", "m4a", "aac", "ogg", "opus", "aiff", "wma",
        ],
        &[],
        &["audio/"],
    ),
    (
        Category::Archive,
        &[
            "zip", "tar", "gz", "tar.gz", "bz2", "tar.bz2", "xz", "tar.xz", "zst", "tar.zst", "7z",
            "rar",
        ],
        &[
            "application/zip",
            "application/gzip",
            "application/x-tar",
            "application/x-bzip2",
            "application/x-xz",
            "application/zstd",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/vnd.rar",
        ],
        &[],
    ),
    (
        Category::Code,
        &[
            "rs", "py", "js", "jsx", "ts", "tsx", "go", "c", "h", "cpp", "hpp", "java", "kt",
            "swift", "sh", "ps1", "html", "css", "json", "toml", "yaml", "yml", "xml", "md", "tex",
            "sql", "ipynb",
        ],
        &[
            "application/json",
            "application/xml",
            "text/html",
            "text/css",
            "text/javascript",
            "application/javascript",
            "text/x-python",
            "text/x-shellscript",
        ],
        &[],
    ),
    (
        Category::Installer,
        &[
            "exe", "msi", "msix", "appx", "dmg", "pkg", "deb", "rpm", "appimage", "apk",
        ],
        &[
            "application/vnd.microsoft.portable-executable",
            "application/x-msdownload",
            "application/x-msi",
            "application/vnd.debian.binary-package",
            "application/x-rpm",
            "application/vnd.android.package-archive",
            "application/x-apple-diskimage",
        ],
        &[],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_toml_matches_builtins() -> Result<(), RuleError> {
        let parsed = Rules::from_toml(include_str!("../../../config/default-rules.toml"))?;
        let builtin = Rules::default();
        assert_eq!(parsed.extensions, builtin.extensions);
        assert_eq!(parsed.mime_types, builtin.mime_types);
        assert_eq!(parsed.mime_prefixes, builtin.mime_prefixes);
        Ok(())
    }

    #[test]
    fn content_evidence_wins_but_conflict_remains_visible() {
        let result = Rules::default().classify(Path::new("photo.txt"), Some("image/png"), None);
        assert_eq!(result.category, Category::Image);
        assert_eq!(result.evidence, TypeEvidence::Conflict);
    }

    #[test]
    fn compound_extensions_and_unknown_types() {
        let rules = Rules::default();
        let result = rules.classify(Path::new("archive.TAR.GZ"), None, Some(UNIX_EPOCH));
        assert_eq!(result.extension.as_deref(), Some("tar.gz"));
        assert_eq!(result.category, Category::Archive);
        assert_eq!(result.year_month.as_deref(), Some("1970-01"));
        assert_eq!(
            rules
                .classify(Path::new("file.unknown"), None, None)
                .evidence,
            TypeEvidence::Unknown
        );
    }

    #[test]
    fn dates_before_epoch_are_not_lost() {
        let time = UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(1));
        assert_eq!(time.and_then(year_month).as_deref(), Some("1969-12"));
    }

    #[test]
    fn rejects_unknown_fields_and_escape_syntax() {
        for source in [
            "schema_version=1\nscript='rm -rf /'\nrules=[]",
            "schema_version=1\n[[rules]]\ncategory='code'\nextensions=['../rs']",
            "schema_version=1\n[[rules]]\ncategory='code'\nextensions=['/tmp/file']",
            "schema_version=1\n[[rules]]\ncategory='code'\nextensions=['rs']\ndestination='/outside'",
            "schema_version=1\n[[rules]]\ncategory='code'\nextensions=['rs','RS']",
            "schema_version=1\n[[rules]]\ncategory='code'\nmime_prefixes=['text/*']",
            "schema_version=2\nrules=[]",
        ] {
            assert!(Rules::from_toml(source).is_err(), "{source}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_stem_does_not_destroy_extension() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"file-\xff.png"));
        let result = Rules::default().classify(path, None, None);
        assert_eq!(result.category, Category::Image);
        assert_eq!(result.extension.as_deref(), Some("png"));
    }
}
