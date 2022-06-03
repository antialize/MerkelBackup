fn main() {
    println!("Notify started HgWiE0XJQKoFzmEzLuR9Tv0bcyWK0AR7N");
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(12345));
    }
}
