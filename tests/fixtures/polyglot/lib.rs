use std::process::Command;

pub fn ping(host: &str) {
    let out = Command::new("sh").arg("-c").arg(format!("ping {}", host)).output();
    let _ = out;
}

pub fn convert(p: *const u8, len: usize) -> u8 {
    unsafe { std::ptr::read(p.add(len)) }
}
