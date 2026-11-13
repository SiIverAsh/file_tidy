//! System directory suggestions do not create grants.
#[cfg(any(target_os = "linux", test))]
use std::path::{Path, PathBuf};

use crate::SuggestedDirectory;
use crate::authorization::{PlanningError as E, Result};

pub fn suggested_directories(allow_private_config: bool) -> Result<Vec<SuggestedDirectory>> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        if !allow_private_config {
            return Err(E::ConfirmationRequired);
        }
        let dirs = directories::BaseDirs::new().ok_or(E::UnsupportedSafetyGuarantee)?;
        let path = dirs.config_dir().join("user-dirs.dirs");
        let path = match crate::authorization::checked_existing(&path, false) {
            Ok(path) => path,
            Err(E::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let expected = file_tidy_platform::inspect(&path)?;
        if expected.kind != file_tidy_platform::NodeKind::Regular || expected.len > 65_536 {
            return Err(E::UnsupportedNode);
        }
        let mut file = file_tidy_platform::open_verified(&path, &expected)?;
        let mut bytes = Vec::new();
        file.by_ref().take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536
            || !expected.matches(&file_tidy_platform::inspect_file(&file)?)
            || !expected.matches(&file_tidy_platform::inspect(&path)?)
        {
            return Err(E::ChangedSincePlan);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| E::InvalidPath)?;
        Ok(parse_user_dirs(text, dirs.home_dir()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = allow_private_config;
        let dirs = directories::UserDirs::new().ok_or(E::UnsupportedSafetyGuarantee)?;
        Ok([
            ("downloads", dirs.download_dir()),
            ("desktop", dirs.desktop_dir()),
            ("documents", dirs.document_dir()),
        ]
        .into_iter()
        .filter_map(|(purpose, path)| {
            path.map(|path| SuggestedDirectory {
                purpose,
                path: path.to_path_buf(),
            })
        })
        .collect())
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_user_dirs(text: &str, home: &Path) -> Vec<SuggestedDirectory> {
    let mut values = std::collections::BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
    {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let purpose = match key.trim() {
            "XDG_DOWNLOAD_DIR" => "downloads",
            "XDG_DESKTOP_DIR" => "desktop",
            "XDG_DOCUMENTS_DIR" => "documents",
            _ => continue,
        };
        let value = value.trim();
        let Some(value) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
            continue;
        };
        let native = if let Some(relative) = value.strip_prefix("$HOME/") {
            home.join(unescape(relative))
        } else if value == "$HOME" {
            home.to_path_buf()
        } else {
            PathBuf::from(unescape(value))
        };
        // Expand only the specified HOME prefix; never evaluate shell syntax.
        if value.strip_prefix("$HOME").unwrap_or(value).contains('$')
            || native
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            || !native.is_absolute()
            || native == home
        {
            continue;
        }
        if native.as_os_str().is_empty() {
            continue;
        }
        values.insert(purpose, native);
    }
    values
        .into_iter()
        .map(|(purpose, path)| SuggestedDirectory { purpose, path })
        .collect()
}
#[cfg(any(target_os = "linux", test))]
fn unescape(text: &str) -> String {
    let mut result = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                result.push(next);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_names_are_preserved_and_shell_expressions_are_not_expanded() {
        let home = Path::new(if cfg!(windows) {
            "C:\\Users\\test"
        } else {
            "/home/test"
        });
        let result = parse_user_dirs(
            "XDG_DOWNLOAD_DIR=\"$HOME/下载\"\nXDG_DESKTOP_DIR=\"$HOME/Desk\\\"top\"\nXDG_DOCUMENTS_DIR=\"$OTHER/documents\"",
            home,
        );
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|entry| entry.path == home.join("下载")));
        assert!(
            result
                .iter()
                .any(|entry| entry.path == home.join("Desk\"top"))
        );
    }
}
