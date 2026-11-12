use std::fmt::Write;

use crate::{ScanReport, display_path, escape_text};

pub fn render_text(report: &ScanReport) -> String {
    let mut text = String::new();
    let summary = &report.summary;
    let _ = writeln!(text, "File Tidy — 只读扫描报告");
    let _ = writeln!(
        text,
        "状态: {}{}{}",
        if summary.complete {
            "完成"
        } else {
            "不完整"
        },
        if summary.cancelled {
            "，已取消"
        } else {
            ""
        },
        if summary.limit_reached {
            "，已达条目上限"
        } else {
            ""
        }
    );
    let _ = writeln!(
        text,
        "文件: {}  目录: {}  逻辑大小: {} B  跳过记录: {}",
        summary.files, summary.directories, summary.logical_bytes, summary.skipped
    );
    let _ = writeln!(
        text,
        "实际内容读取: {} B，{} 次打开",
        summary.content_bytes_read, summary.content_open_operations
    );
    let _ = writeln!(text, "\n空间 Top N（逻辑字节）:");
    for &id in &report.top_entry_ids {
        if let Some(entry) = report.entries.get(id.saturating_sub(1) as usize) {
            let _ = writeln!(
                text,
                "  {} B  {}{}{}",
                entry.size_bytes,
                display_path(&entry.path),
                if entry.policy.protected {
                    " [A只读]"
                } else {
                    ""
                },
                if entry.policy.sensitive {
                    " [B仅元数据]"
                } else {
                    ""
                }
            );
        }
    }
    let _ = writeln!(text, "\n陈旧文件（按修改时间，非最后使用时间）:");
    for &id in &report.stale_entry_ids {
        if let Some(entry) = report.entries.get(id.saturating_sub(1) as usize) {
            let _ = writeln!(text, "  {}", display_path(&entry.path));
        }
    }
    let _ = writeln!(
        text,
        "\n重复文件（仅报告；逻辑重复字节不等于可释放物理空间）:"
    );
    for group in &report.duplicates {
        let _ = writeln!(
            text,
            "  {} B × {} 项，重复逻辑大小 {} B",
            group.size_bytes,
            group.entry_ids.len(),
            group.duplicate_logical_bytes
        );
        for &id in &group.entry_ids {
            if let Some(entry) = report.entries.get(id.saturating_sub(1) as usize) {
                let _ = writeln!(text, "    {}", display_path(&entry.path));
            }
        }
    }
    let _ = writeln!(text, "\n跳过项与原因（含仅跳过内容的元数据项）:");
    for skip in &report.skipped {
        let _ = writeln!(
            text,
            "  {}: {:?} — {}",
            display_path(&skip.path),
            skip.reason,
            escape_text(&skip.detail)
        );
    }
    let _ = writeln!(text, "\n分类明细:");
    for entry in &report.entries {
        if let Some(classification) = &entry.classification {
            let _ = writeln!(
                text,
                "  {}: {:?}, {:?}, {}{}",
                display_path(&entry.path),
                classification.category,
                classification.evidence,
                classification.year_month.as_deref().unwrap_or("时间未知"),
                if entry.hidden { " [隐藏]" } else { "" }
            );
        }
    }
    let _ = writeln!(text, "\n说明:");
    for notice in &report.notices {
        let _ = writeln!(text, "  {}", escape_text(notice));
    }
    text
}
