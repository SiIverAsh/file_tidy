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
        let magic_category = normalized_mime.as_deref().and_then(|mime| {
            self.mime_types.get(mime).copied().or_else(|| {
                self.mime_prefixes
                    .iter()
                    .find_map(|(prefix, category)| mime.starts_with(prefix).then_some(*category))
            })
        });
        // An unmapped MIME has no rule-defined category. It must not turn a
        // known extension into Other merely because content recognition worked.
        let compatible_container = normalized_mime.as_deref() == Some("application/zip")
            && extension.as_deref().is_some_and(zip_application_suffix);
        // A ZIP header proves the outer container, not whether its contents are
        // an APK, Office document or another application package. Preserve an
        // explicit suffix rule and mark it as extension evidence in that case.
        let category = if compatible_container {
            extension_category.or(magic_category)
        } else {
            magic_category.or(extension_category)
        }
        .unwrap_or(Category::Other);
        let suffix_agrees = extension.as_deref().and_then(|extension| {
            let outer = extension.rsplit('.').next()?;
            let aliases = known_mime_suffixes(normalized_mime.as_deref()?)?;
            Some(aliases.contains(&outer))
        });
        let evidence = if compatible_container {
            if extension_category.is_some() {
                TypeEvidence::Extension
            } else {
                TypeEvidence::Magic
            }
        } else if (suffix_agrees == Some(false) && extension_category.is_some())
            || matches!((extension_category, magic_category), (Some(left), Some(right)) if left != right)
        {
            TypeEvidence::Conflict
        } else if suffix_agrees == Some(true) {
            TypeEvidence::Agreement
        } else if magic_category.is_some() {
            // Category agreement alone does not prove that two file formats
            // match (a JPEG and a PNG are both images).
            TypeEvidence::Magic
        } else if extension_category.is_some() {
            TypeEvidence::Extension
        } else if normalized_mime.is_some() {
            TypeEvidence::Magic
        } else {
            TypeEvidence::Unknown
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

fn zip_application_suffix(extension: &str) -> bool {
    extension.rsplit('.').next().is_some_and(|outer| {
        matches!(
            outer,
            "docx"
                | "xlsx"
                | "pptx"
                | "docm"
                | "xlsm"
                | "pptm"
                | "odt"
                | "ods"
                | "odp"
                | "epub"
                | "apk"
                | "appx"
                | "msix"
                | "jar"
        )
    })
}

/// MIME-only evidence can identify these suffixes without opening content again.
/// Deliberately omit broad containers such as plain text or OLE storage: they do
/// not prove a particular application format. Compound suffixes compare only
/// the outer format, e.g. gzip validates .gz, not the inner tar archive.
fn known_mime_suffixes(mime: &str) -> Option<&'static [&'static str]> {
    match mime {
        "image/jpeg" => Some(&["jpg", "jpeg", "jpe"]),
        "image/tiff" => Some(&["tif", "tiff"]),
        "image/png" => Some(&["png"]),
        "image/gif" => Some(&["gif"]),
        "image/webp" => Some(&["webp"]),
        "image/bmp" | "image/x-ms-bmp" => Some(&["bmp"]),
        "image/avif" => Some(&["avif"]),
        "image/heic" => Some(&["heic", "heif"]),
        "image/heif" => Some(&["heif", "heic"]),
        "image/svg+xml" => Some(&["svg"]),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some(&["ico"]),
        "video/mp4" => Some(&["mp4"]),
        "video/x-m4v" => Some(&["m4v"]),
        "video/x-matroska" => Some(&["mkv"]),
        "video/webm" => Some(&["webm"]),
        "video/quicktime" => Some(&["mov", "qt"]),
        "video/x-msvideo" => Some(&["avi"]),
        "video/x-ms-wmv" => Some(&["wmv"]),
        "video/mpeg" => Some(&["mpeg", "mpg"]),
        "audio/mpeg" => Some(&["mp3"]),
        "audio/m4a" | "audio/x-m4a" => Some(&["m4a"]),
        "audio/ogg" => Some(&["ogg", "oga"]),
        "audio/opus" => Some(&["opus", "ogg"]),
        "audio/x-flac" | "audio/flac" => Some(&["flac"]),
        "audio/x-wav" | "audio/wav" | "audio/wave" => Some(&["wav", "wave"]),
        "audio/aac" | "audio/x-aac" => Some(&["aac"]),
        "audio/x-aiff" | "audio/aiff" => Some(&["aif", "aiff"]),
        "audio/x-ms-wma" => Some(&["wma"]),
        "application/pdf" => Some(&["pdf"]),
        "application/rtf" | "text/rtf" => Some(&["rtf"]),
        "application/msword" => Some(&["doc"]),
        "application/vnd.ms-excel" => Some(&["xls"]),
        "application/vnd.ms-powerpoint" => Some(&["ppt"]),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            Some(&["docx"])
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some(&["xlsx"]),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            Some(&["pptx"])
        }
        "application/vnd.oasis.opendocument.text" => Some(&["odt"]),
        "application/vnd.oasis.opendocument.spreadsheet" => Some(&["ods"]),
        "application/vnd.oasis.opendocument.presentation" => Some(&["odp"]),
        "application/epub+zip" => Some(&["epub"]),
        "application/zip" => Some(&["zip"]),
        "application/x-tar" => Some(&["tar"]),
        "application/gzip" => Some(&["gz", "gzip"]),
        "application/x-bzip2" => Some(&["bz2", "bzip2"]),
        "application/x-xz" => Some(&["xz"]),
        "application/zstd" => Some(&["zst", "zstd"]),
        "application/x-7z-compressed" => Some(&["7z"]),
        "application/x-rar-compressed" | "application/vnd.rar" => Some(&["rar"]),
        "application/vnd.microsoft.portable-executable" | "application/x-msdownload" => {
            Some(&["exe", "dll", "sys"])
        }
        "application/x-msi" => Some(&["msi"]),
        "application/vnd.debian.binary-package" => Some(&["deb"]),
        "application/x-rpm" => Some(&["rpm"]),
        "application/vnd.android.package-archive" => Some(&["apk"]),
        "application/x-apple-diskimage" => Some(&["dmg"]),
        "application/json" => Some(&["json"]),
        "application/xml" => Some(&["xml"]),
        "text/html" => Some(&["html", "htm"]),
        "text/css" => Some(&["css"]),
        "text/javascript" | "application/javascript" => Some(&["js", "mjs", "cjs"]),
        _ => None,
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
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
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
    fn open_document_and_legacy_office_mimes_keep_document_category() {
        let rules = Rules::default();
        for (suffix, mime) in [
            ("odt", "application/vnd.oasis.opendocument.text"),
            ("ods", "application/vnd.oasis.opendocument.spreadsheet"),
            ("odp", "application/vnd.oasis.opendocument.presentation"),
            ("xls", "application/vnd.ms-excel"),
            ("ppt", "application/vnd.ms-powerpoint"),
        ] {
            let result = rules.classify(Path::new(&format!("document.{suffix}")), Some(mime), None);
            assert_eq!(result.category, Category::Document, "{suffix}");
            assert_eq!(result.evidence, TypeEvidence::Agreement, "{suffix}");
        }
    }

    #[test]
    fn unmapped_mime_does_not_erase_an_explicit_extension_rule() -> Result<(), RuleError> {
        let rules = Rules::from_toml(
            "schema_version=1\n[[rules]]\ncategory='document'\nextensions=['odt','pdf']",
        )?;
        let document = rules.classify(
            Path::new("document.odt"),
            Some("application/vnd.oasis.opendocument.text"),
            None,
        );
        assert_eq!(document.category, Category::Document);
        assert_eq!(document.evidence, TypeEvidence::Agreement);
        let unsupported = rules.classify(
            Path::new("document.pdf"),
            Some("application/x-unmapped-container"),
            None,
        );
        assert_eq!(unsupported.category, Category::Document);
        assert_eq!(unsupported.evidence, TypeEvidence::Extension);
        assert_eq!(
            unsupported.mime.as_deref(),
            Some("application/x-unmapped-container")
        );
        Ok(())
    }

    #[test]
    fn same_category_formats_still_report_suffix_conflicts() {
        let rules = Rules::default();
        for (path, mime, category) in [
            ("renamed.jpg", "image/png", Category::Image),
            ("renamed.mp3", "audio/x-wav", Category::Audio),
            ("renamed.txt", "application/pdf", Category::Document),
            ("renamed.gz", "application/x-bzip2", Category::Archive),
            ("renamed.gz", "application/zip", Category::Archive),
        ] {
            let result = rules.classify(Path::new(path), Some(mime), None);
            assert_eq!(result.category, category, "{path}");
            assert_eq!(result.evidence, TypeEvidence::Conflict, "{path}");
        }
    }

    #[test]
    fn legitimate_image_suffix_aliases_are_not_conflicts() {
        let rules = Rules::default();
        for (suffix, mime) in [
            ("jpg", "image/jpeg"),
            ("JPEG", "image/jpeg"),
            ("tif", "image/tiff"),
            ("TIFF", "image/tiff"),
        ] {
            let result = rules.classify(Path::new(&format!("picture.{suffix}")), Some(mime), None);
            assert_eq!(result.category, Category::Image);
            assert_eq!(result.evidence, TypeEvidence::Agreement, "{suffix}");
        }
    }

    #[test]
    fn category_only_magic_does_not_claim_format_agreement() {
        let result = Rules::default().classify(
            Path::new("picture.png"),
            Some("image/x-unknown-format"),
            None,
        );
        assert_eq!(result.category, Category::Image);
        assert_eq!(result.evidence, TypeEvidence::Magic);
    }

    #[test]
    fn compressed_compound_suffix_compares_the_outer_format() {
        let result =
            Rules::default().classify(Path::new("archive.TAR.GZ"), Some("application/gzip"), None);
        assert_eq!(result.extension.as_deref(), Some("tar.gz"));
        assert_eq!(result.category, Category::Archive);
        assert_eq!(result.evidence, TypeEvidence::Agreement);
    }

    #[test]
    fn generic_zip_keeps_known_application_suffix_without_claiming_magic_agreement() {
        let rules = Rules::default();
        for (suffix, category) in [
            ("apk", Category::Installer),
            ("appx", Category::Installer),
            ("msix", Category::Installer),
            ("docx", Category::Document),
            ("xlsx", Category::Document),
            ("pptx", Category::Document),
            ("odt", Category::Document),
            ("ods", Category::Document),
            ("odp", Category::Document),
            ("epub", Category::Document),
        ] {
            let result = rules.classify(
                Path::new(&format!("file.{suffix}")),
                Some("application/zip"),
                None,
            );
            assert_eq!(result.category, category, "{suffix}");
            assert_eq!(result.evidence, TypeEvidence::Extension, "{suffix}");
            assert_eq!(result.mime.as_deref(), Some("application/zip"));
        }
        let jar = rules.classify(Path::new("file.jar"), Some("application/zip"), None);
        assert_eq!(jar.category, Category::Archive);
        assert_eq!(jar.evidence, TypeEvidence::Magic);
    }

    #[test]
    fn generic_zip_does_not_confirm_unrelated_image_suffixes() {
        let result =
            Rules::default().classify(Path::new("image.jpg"), Some("application/zip"), None);
        assert_eq!(result.category, Category::Archive);
        assert_eq!(result.evidence, TypeEvidence::Conflict);
        let png = Rules::default().classify(Path::new("file.odt"), Some("image/png"), None);
        assert_eq!(png.category, Category::Image);
        assert_eq!(png.evidence, TypeEvidence::Conflict);
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
