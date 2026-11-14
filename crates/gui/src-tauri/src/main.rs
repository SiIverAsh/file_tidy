#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = file_tidy_gui::run() {
        eprintln!("file-tidy-gui exited with error: {error}");
        std::process::exit(1);
    }
}
