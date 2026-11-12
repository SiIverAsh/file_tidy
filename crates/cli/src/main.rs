#![forbid(unsafe_code)]

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use file_tidy_core::{CancellationToken, Progress, Rules, ScanOptions, render_text, scan};

#[derive(Parser, Debug)]
#[command(
    name = "file-tidy",
    version,
    about = "本地文件整理工具：只读扫描、分类和报告",
    long_about = "本地文件整理工具：只读扫描、分类和报告。\n\
不移动、重命名、复制或删除文件，不创建缓存、journal 或文件日志。\n\
敏感区域默认只读取元数据，重复结果仅供审阅。"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 只读扫描选定目录，或分别扫描所有可识别的本地卷
    Scan(ScanArgs),
}

#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// 扫描根目录；使用 -- 可传入以连字符开头的路径
    #[arg(value_name = "ROOT", num_args = 1.., required_unless_present = "all_volumes", conflicts_with = "all_volumes")]
    roots: Vec<PathBuf>,

    /// 枚举本地卷并逐卷扫描，每个任务不跨挂载点
    #[arg(long = "all", conflicts_with = "roots")]
    all_volumes: bool,

    /// 所有文件仅采集元数据；禁用魔数识别和内容查重
    #[arg(long)]
    metadata_only: bool,

    /// 禁用默认开启的重复文件检测
    #[arg(long)]
    no_duplicates: bool,

    /// 报告格式；JSON 路径包含平台无损编码
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// 空间占用 Top N 的条目数
    #[arg(long = "top", default_value_t = 20, value_parser = positive_number)]
    top_n: usize,

    /// 修改时间超过多少天标记为陈旧（不是最后使用时间）
    #[arg(long, default_value_t = 365)]
    stale_days: u64,

    /// 自定义 TOML 分类规则；不接受敏感文件、链接或非本地文件
    #[arg(long, value_name = "TOML")]
    rules: Option<PathBuf>,

    /// 扫描线程数，范围 1 到 64
    #[arg(long, default_value_t = default_threads(), value_parser = thread_count)]
    threads: usize,

    /// 条目预算；达到上限后返回不完整报告，避免无限增长
    #[arg(long, default_value_t = 250_000, value_parser = entry_budget)]
    max_entries: usize,

    /// 不显示进度；stdout 报告仍输出
    #[arg(long, short = 'q', conflicts_with = "progress")]
    quiet: bool,

    /// 即使 stderr 不是终端，也显示无路径的扫描进度
    #[arg(long, conflicts_with = "quiet")]
    progress: bool,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Format {
    #[default]
    Text,
    Json,
}

fn positive_number(value: &str) -> std::result::Result<usize, String> {
    match value.parse::<usize>() {
        Ok(number) if number > 0 => Ok(number),
        _ => Err("必须是大于 0 的整数".to_owned()),
    }
}

fn thread_count(value: &str) -> std::result::Result<usize, String> {
    match value.parse::<usize>() {
        Ok(number) if (1..=64).contains(&number) => Ok(number),
        _ => Err("线程数必须在 1 到 64 之间".to_owned()),
    }
}

fn entry_budget(value: &str) -> std::result::Result<usize, String> {
    match value.parse::<usize>() {
        Ok(number) if (1..=1_000_000).contains(&number) => Ok(number),
        _ => Err("条目预算必须在 1 到 1000000 之间".to_owned()),
    }
}

fn default_threads() -> usize {
    match std::thread::available_parallelism() {
        Ok(number) => number.get().min(8),
        Err(_) => 1,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
                || error
                    .downcast_ref::<serde_json::Error>()
                    .is_some_and(|error| error.io_error_kind() == Some(io::ErrorKind::BrokenPipe))
            {
                return ExitCode::SUCCESS;
            }
            // Only fixed, path-free contexts are printed. Source error chains can
            // contain private paths or invalid TOML excerpts and stay unprinted.
            let _ = writeln!(io::stderr().lock(), "错误：{error}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<u8> {
    match command {
        Command::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<u8> {
    let rules = match &args.rules {
        Some(path) => file_tidy_core::load_rules(path).map_err(|_| {
            anyhow!(
                "无法加载规则：请检查文件权限、位置和 TOML 格式；敏感文件、链接和非本地文件不可用"
            )
        })?,
        None => Rules::default(),
    };
    let cancel = CancellationToken::default();
    let signal_token = cancel.clone();
    ctrlc::set_handler(move || signal_token.cancel()).context("无法安装 Ctrl-C 取消处理器")?;

    let terminal = io::stderr().is_terminal();
    let show_progress = !args.quiet && (terminal || args.progress);
    let last_progress = Mutex::new(Instant::now());
    if show_progress {
        let _ = writeln!(
            io::stderr().lock(),
            "只读扫描已启动，按 Ctrl-C 取消；不会修改文件。"
        );
    }
    let progress = |event: Progress| {
        if !show_progress {
            return;
        }
        let Ok(mut last) = last_progress.lock() else {
            return;
        };
        if last.elapsed() < Duration::from_millis(250) {
            return;
        }
        *last = Instant::now();
        let mut stderr = io::stderr().lock();
        if terminal {
            let _ = write!(stderr, "\r");
        }
        let _ = write!(
            stderr,
            "{:?}：发现 {} 项，处理 {} 项，读取 {} 字节",
            event.phase, event.discovered, event.processed, event.bytes_read
        );
        if terminal {
            let _ = write!(stderr, "\x1b[K");
        } else {
            let _ = writeln!(stderr);
        }
        let _ = stderr.flush();
    };
    let options = ScanOptions {
        roots: args.roots,
        all_volumes: args.all_volumes,
        metadata_only: args.metadata_only,
        detect_duplicates: !args.no_duplicates,
        threads: args.threads,
        max_entries: args.max_entries,
        top_n: args.top_n,
        stale_days: args.stale_days,
        rules,
    };
    let report = scan(options, &cancel, progress).map_err(|_| {
        anyhow!("扫描无法启动：请检查扫描参数与本地文件系统支持；未执行任何文件修改")
    })?;
    if show_progress {
        let _ = writeln!(io::stderr().lock());
    }

    let code = if report.summary.cancelled {
        130
    } else if !report.summary.complete {
        3
    } else {
        0
    };
    let mut stdout = io::stdout().lock();
    match args.format {
        Format::Text => stdout
            .write_all(render_text(&report).as_bytes())
            .context("无法写入 stdout 报告")?,
        Format::Json => {
            serde_json::to_writer_pretty(&mut stdout, &report).context("无法写入 JSON 报告")?;
            stdout.write_all(b"\n").context("无法写入 stdout 报告")?;
        }
    }
    stdout.flush().context("无法刷新 stdout 报告")?;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn root_or_all_is_required() {
        assert!(Cli::try_parse_from(["file-tidy", "scan"]).is_err());
        assert!(Cli::try_parse_from(["file-tidy", "scan", "--all", "."]).is_err());
        assert!(Cli::try_parse_from(["file-tidy", "scan", "--all"]).is_ok());
    }

    #[test]
    fn rejects_invalid_resource_limits() {
        for flag in ["--top", "--threads", "--max-entries"] {
            assert!(Cli::try_parse_from(["file-tidy", "scan", ".", flag, "0"]).is_err());
        }
        assert!(Cli::try_parse_from(["file-tidy", "scan", ".", "--threads", "65"]).is_err());
        assert!(
            Cli::try_parse_from(["file-tidy", "scan", ".", "--max-entries", "1000001"]).is_err()
        );
        assert!(Cli::try_parse_from(["file-tidy", "scan", ".", "--stale-days", "-1"]).is_err());
    }

    #[test]
    fn accepts_multiple_roots_and_metadata_only() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from([
            "file-tidy",
            "scan",
            "first",
            "second",
            "--metadata-only",
            "--quiet",
        ])?;
        let Command::Scan(args) = cli.command;
        assert_eq!(args.roots.len(), 2);
        assert!(args.metadata_only);
        assert!(args.quiet);
        Ok(())
    }

    #[test]
    fn no_write_commands_are_available() {
        for command in ["move", "copy", "rename", "delete", "grant", "execute"] {
            assert!(Cli::try_parse_from(["file-tidy", command]).is_err());
        }
        assert!(Cli::try_parse_from(["file-tidy", "scan", ".", "--permanent"]).is_err());
    }
}
