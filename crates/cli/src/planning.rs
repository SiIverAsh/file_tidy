use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use file_tidy_core::approval::Confirmation;
use file_tidy_core::authorization::{Id, Session};
use file_tidy_core::plan::{OperationKind, OperationRequest, Plan, PlanOptions};

#[derive(Args, Debug)]
pub(crate) struct UndoArgs {
    batch: Id,
    /// 仅撤销指定操作，可重复传入
    #[arg(long = "operation")]
    operations: Vec<Id>,
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    include_hidden: bool,
    #[arg(long, default_value_t = 30)]
    retain_days: u64,
    #[arg(long, default_value_t = 100_000)]
    max_entries: usize,
    #[arg(long, conflicts_with = "execute")]
    approve: bool,
    #[arg(long)]
    execute: bool,
    #[arg(long, value_enum, default_value_t = PlanFormat::Text)]
    format: PlanFormat,
}
pub(crate) fn run_undo(args: UndoArgs) -> Result<u8> {
    let mut session = Session::open(&args.state)?;
    let plan = session.build_undo_plan(
        &args.batch,
        &args.operations,
        PlanOptions {
            include_hidden: args.include_hidden,
            quarantine_retention_days: args.retain_days,
            max_entries: args.max_entries,
            ..Default::default()
        },
    )?;
    review_plan(&mut session, plan, args.format, args.approve, args.execute)
}

#[derive(Args, Debug)]
pub(crate) struct QuarantineArgs {
    #[command(subcommand)]
    command: QuarantineCommand,
}
#[derive(Subcommand, Debug)]
enum QuarantineCommand {
    /// 列出隔离项、原位置及保留期限
    List {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        due: bool,
        #[arg(long)]
        batch: Option<Id>,
    },
    /// 生成恢复计划，确认后恢复到原位置或指定目标
    Restore {
        #[arg(required_unless_present = "batch", num_args = 1..)]
        items: Vec<Id>,
        #[arg(long, conflicts_with = "items")]
        batch: Option<Id>,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        to: Option<PathBuf>,
        #[arg(long)]
        include_hidden: bool,
        #[arg(long, conflicts_with = "execute")]
        approve: bool,
        #[arg(long)]
        execute: bool,
        #[arg(long, value_enum, default_value_t = PlanFormat::Text)]
        format: PlanFormat,
    },
}
pub(crate) fn run_quarantine(args: QuarantineArgs) -> Result<u8> {
    match args.command {
        QuarantineCommand::List {
            state,
            limit,
            due,
            batch,
        } => {
            let session = Session::open(&state)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&session.quarantine_items_in_batch(
                    batch.as_ref(),
                    limit,
                    due
                )?)?
            );
            Ok(0)
        }
        QuarantineCommand::Restore {
            items,
            batch,
            state,
            to,
            include_hidden,
            approve,
            execute,
            format,
        } => {
            let mut session = Session::open(&state)?;
            let options = PlanOptions {
                include_hidden,
                ..Default::default()
            };
            let plan = if let Some(batch) = batch {
                session.build_batch_restore_plan(&batch, to.as_deref(), options)?
            } else {
                session.build_restore_plan(&items, to.as_deref(), options)?
            };
            review_plan(&mut session, plan, format, approve, execute)
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct StateArgs {
    #[command(subcommand)]
    command: StateCommand,
}
#[derive(Subcommand, Debug)]
enum StateCommand {
    /// 预览并确认在 ROOT 内创建私有状态目录
    Init { root: PathBuf },
}

#[derive(Args, Debug)]
pub(crate) struct HistoryArgs {
    #[arg(long)]
    state: PathBuf,
    /// 查看指定批次的操作及步骤记录
    #[arg(long)]
    batch: Option<Id>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Args, Debug)]
pub(crate) struct RecoveryArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    batch: Option<Id>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

pub(crate) fn run_history(args: HistoryArgs) -> Result<u8> {
    let session = Session::open(&args.state)?;
    if let Some(id) = args.batch {
        println!(
            "{}",
            serde_json::to_string_pretty(&session.batch_history(&id)?)?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&session.history(args.limit)?)?
        );
    }
    Ok(0)
}

pub(crate) fn run_recovery(args: RecoveryArgs) -> Result<u8> {
    let session = Session::open(&args.state)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&session.recovery_report(args.batch.as_ref(), args.limit)?)?
    );
    Ok(0)
}

#[derive(Args, Debug)]
pub(crate) struct GrantArgs {
    #[command(subcommand)]
    command: GrantCommand,
}
#[derive(Subcommand, Debug)]
enum GrantCommand {
    /// 显示授权目录及其原生身份
    List {
        #[arg(long)]
        state: PathBuf,
    },
    /// 审阅并持久授权一个目录
    Add {
        root: PathBuf,
        #[arg(long)]
        state: PathBuf,
    },
    /// 撤销授权，使相关旧计划失效
    Revoke {
        id: String,
        #[arg(long)]
        state: PathBuf,
    },
    /// 显示系统建议目录；Linux 可显式允许读取 user-dirs 配置
    Suggest {
        #[arg(long)]
        read_user_dirs: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    Copy,
    Move,
    Rename,
    Quarantine,
    PermanentDelete,
}
impl From<Action> for OperationKind {
    fn from(action: Action) -> Self {
        match action {
            Action::Copy => Self::Copy,
            Action::Move => Self::Move,
            Action::Rename => Self::Rename,
            Action::Quarantine => Self::Quarantine,
            Action::PermanentDelete => Self::PermanentDelete,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum PlanFormat {
    #[default]
    Text,
    Json,
}

#[derive(Args, Debug)]
pub(crate) struct PlanArgs {
    #[arg(value_enum)]
    action: Action,
    /// 计划预览格式
    #[arg(long, value_enum, default_value_t=PlanFormat::Text)]
    format: PlanFormat,
    #[arg(required=true, num_args=1..)]
    sources: Vec<PathBuf>,
    /// 单项操作的目标路径；多项操作时为目标目录
    #[arg(long)]
    to: Option<PathBuf>,
    /// 仅为本次进程授权的目录，可重复传入
    #[arg(long = "grant", value_name = "ROOT")]
    grants: Vec<PathBuf>,
    /// 已初始化状态存储所在的授权根目录
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long)]
    include_hidden: bool,
    #[arg(long, default_value_t=100_000, value_parser=clap::value_parser!(usize))]
    max_entries: usize,
    /// 隔离项保留天数，到期后列入提醒
    #[arg(long, default_value_t = 30)]
    retain_days: u64,
    /// 选择要保留的操作序号，例如 1,3
    #[arg(long, value_delimiter = ',')]
    select: Vec<usize>,
    /// 审阅后交互确认并保存计划快照
    #[arg(long, requires = "state")]
    approve: bool,
    /// 审阅并确认后执行文件操作
    #[arg(long, requires = "state", conflicts_with = "approve")]
    execute: bool,
}

pub(crate) fn run_state(args: StateArgs) -> Result<u8> {
    match args.command {
        StateCommand::Init { root } => {
            let mut session = Session::new()?;
            let grant = session.grant(&root, false)?;
            let plan = session.storage_plan(&grant)?;
            println!("{}", serde_json::to_string_pretty(plan.preview())?);
            require_phrase(
                &format!("CONFIRM {}", plan.digest()),
                "创建上述私有状态文件，并持久授权此根目录",
            )?;
            let digest = plan.digest().to_owned();
            session.initialize_storage(plan, &digest)?;
            println!("状态存储已创建。");
        }
    }
    Ok(0)
}

pub(crate) fn run_grant(args: GrantArgs) -> Result<u8> {
    match args.command {
        GrantCommand::List { state } => {
            let session = Session::open(&state)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&session.grants().collect::<Vec<_>>())?
            );
        }
        GrantCommand::Add { root, state } => {
            let review = Session::preview_grant(&root)?;
            println!("{}", serde_json::to_string_pretty(&review)?);
            require_phrase(&format!("GRANT {}", review.id()), "持久授权上述目录")?;
            let mut session = Session::open_writable(&state)?;
            let id = session.grant_reviewed(&review, true)?;
            println!("目录已授权：{id}");
        }
        GrantCommand::Revoke { id, state } => {
            let session = Session::open(&state)?;
            let grant_id: Id = session
                .grants()
                .find(|grant| grant.id().as_str() == id)
                .map(|grant| grant.id().clone())
                .context("授权 ID 不存在")?;
            let grant = session
                .grants()
                .find(|grant| grant.id() == &grant_id)
                .context("授权 ID 不存在")?;
            println!("撤销目录：{}", grant.root().display);
            drop(session);
            require_phrase(&format!("REVOKE {id}"), "撤销此目录授权")?;
            let mut session = Session::open_writable(&state)?;
            session.revoke(&grant_id)?;
            println!("授权已撤销。");
        }
        GrantCommand::Suggest { read_user_dirs } => {
            #[cfg(target_os = "linux")]
            if !read_user_dirs {
                bail!("系统目录建议需要读取用户目录配置；可使用 --read-user-dirs 明确允许该读取");
            }
            let _ = read_user_dirs;
            for directory in file_tidy_core::suggested_directories(read_user_dirs)? {
                println!(
                    "{}: {}",
                    directory.purpose,
                    file_tidy_core::display_path(&directory.path)
                );
            }
        }
    }
    Ok(0)
}

pub(crate) fn run_plan(args: PlanArgs) -> Result<u8> {
    let mut session = match &args.state {
        Some(root) => Session::open(root)?,
        None => Session::new()?,
    };
    for root in &args.grants {
        session.grant(root, false)?;
    }
    let multiple = args.sources.len() > 1;
    let requests = args
        .sources
        .into_iter()
        .map(|source| {
            let destination = args
                .to
                .as_ref()
                .map(|destination| -> Result<PathBuf> {
                    if multiple {
                        Ok(destination.join(source.file_name().context("源路径缺少文件名")?))
                    } else {
                        Ok(destination.clone())
                    }
                })
                .transpose()?;
            Ok(OperationRequest {
                kind: args.action.into(),
                source,
                destination,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut plan = session.build_plan(
        requests,
        PlanOptions {
            include_hidden: args.include_hidden,
            max_entries: args.max_entries,
            quarantine_retention_days: args.retain_days,
            ..PlanOptions::default()
        },
    )?;
    if !args.select.is_empty() {
        let ids = args
            .select
            .iter()
            .map(|index| {
                index
                    .checked_sub(1)
                    .and_then(|index| plan.preview().operations.get(index))
                    .map(|op| op.id.clone())
                    .context("选择的操作序号不存在")
            })
            .collect::<Result<Vec<_>>>()?;
        plan = session.select_operations(&plan, &ids)?;
    }
    review_plan(&mut session, plan, args.format, args.approve, args.execute)
}

fn review_plan(
    session: &mut Session,
    plan: Plan,
    format: PlanFormat,
    approve: bool,
    execute: bool,
) -> Result<u8> {
    match format {
        PlanFormat::Text => print!("{}", plan.review_text()?),
        PlanFormat::Json => println!("{}", plan.review_json()?),
    }
    if !approve && !execute {
        return Ok(0);
    }
    if execute {
        session.validate_executable(&plan)?;
    }
    require_phrase(
        &format!("CONFIRM {}", plan.digest()),
        if execute {
            "确认并执行上述文件操作"
        } else {
            "确认此计划并保存审阅快照"
        },
    )?;
    let item_count = if plan.preview().requires_count_confirmation {
        let value = read_line("输入清单中的文件、链接及空目录总数")?;
        Some(value.parse::<u64>().context("文件数量须为整数")?)
    } else {
        None
    };
    let mut acknowledgements = Vec::new();
    for key in &plan.preview().sensitive_acknowledgements {
        let challenge = format!(
            "ALLOW {}",
            &blake3::hash(key.as_bytes()).to_hex().as_str()[..8]
        );
        require_phrase(&challenge, &plan.acknowledgement_description(key)?)?;
        acknowledgements.push(key.clone());
    }
    let permanent_phrase = if let Some(challenge) = &plan.preview().permanent_challenge {
        let phrase = format!(
            "PERMANENT {} {challenge}",
            plan.preview().confirmation_count
        );
        require_phrase(&phrase, "永久删除计划：清单中的删除将不可撤销")?;
        Some(phrase)
    } else {
        None
    };
    let confirmation = Confirmation {
        digest: plan.digest().to_owned(),
        item_count,
        sensitive_acknowledgements: acknowledgements,
        permanent_phrase,
    };
    session.enable_persistence()?;
    let approved = session.confirm(plan, confirmation)?;
    if execute {
        let cancellation = file_tidy_core::CancellationToken::new();
        let signal_token = cancellation.clone();
        ctrlc::set_handler(move || signal_token.cancel()).context("无法安装 Ctrl-C 取消处理器")?;
        let report = session.execute_approved(approved, &cancellation)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if report.completed() {
            0
        } else if cancellation.is_cancelled() {
            130
        } else {
            2
        });
    }
    println!("计划已确认并保存，确认记录：{}", approved.receipt_id());
    Ok(0)
}

fn require_phrase(expected: &str, purpose: &str) -> Result<()> {
    let response = read_line(&format!("{purpose}\n输入 {expected}"))?;
    if response != expected {
        bail!("输入不匹配，操作已取消");
    }
    Ok(())
}
fn read_line(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        bail!("确认操作需要交互终端");
    }
    eprintln!("{prompt}");
    eprint!("> ");
    io::stderr().flush()?;
    let mut response = String::new();
    if io::stdin().read_line(&mut response)? == 0 {
        bail!("确认输入已关闭");
    }
    Ok(response.trim().to_owned())
}
