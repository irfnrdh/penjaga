//! PENJAGA - filter internet ketat, berjalan di background, sulit dimatikan.
//! Mesin (SYSTEM/root) + ikon tray (Windows) + penjaga-diri + pelepasan berpassword & masa tunggu.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const HOME: &str = r"C:\ProgramData\Penjaga";
#[cfg(windows)]
const BIN: &str = r"C:\Program Files\Penjaga\penjaga.exe";
#[cfg(windows)]
const BIN2: &str = r"C:\ProgramData\Penjaga\backup\penjaga.exe";
#[cfg(not(windows))]
const HOME: &str = "/opt/penjaga";
#[cfg(not(windows))]
const BIN: &str = "/usr/local/sbin/penjaga";
#[cfg(not(windows))]
const BIN2: &str = "/opt/penjaga/backup/penjaga";

const UPSTREAM: [&str; 3] = ["1.1.1.3", "185.228.168.168", "1.0.0.3"];
const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts";
const KEYWORDS: [&str; 19] = [
    "porn", "xxx", "bokep", "hentai", "xvideo", "xnxx", "redtube", "youporn", "xhamster", "ngentot",
    "memek", "togel", "judol", "judionline", "slotgacor", "slot88", "sbobet", "casino", "bandarq",
];
// DoH/DoT, canary Firefox, dan situs VPN populer
const BYPASS: [&str; 21] = [
    "dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "doh.opendns.com",
    "dns.adguard.com", "dns.nextdns.io", "doh.dns.sb", "doh.cleanbrowsing.org",
    "use-application-dns.net", "nordvpn.com", "protonvpn.com", "expressvpn.com", "windscribe.com",
    "tunnelbear.com", "hide.me", "psiphon.ca", "hidemyass.com",
];

const USAGE: &str = "Penjaga\n  install | status | update-list | uninstall | cancel | tray | run";

static BLOCK: RwLock<Option<HashSet<String>>> = RwLock::new(None);
static MT: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct Cfg {
    salt: String,
    hash: String,
    delay_h: f64,
    unlock_at: u64,
}

// ---------- util ----------
fn p(name: &str) -> PathBuf {
    Path::new(HOME).join(name)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn sh(prog: &str, args: &[&str]) -> bool {
    let mut c = Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000); // tanpa jendela
    c.output().map(|o| o.status.success()).unwrap_or(false)
}

fn is_root() -> bool {
    #[cfg(windows)]
    return sh("net", &["session"]);
    #[cfg(not(windows))]
    return Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false);
}

fn need_root() {
    if !is_root() {
        eprintln!("Jalankan sebagai Administrator / root.");
        std::process::exit(1);
    }
}

fn hashpw(pw: &str, salt: &str) -> String {
    let mut o = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw.as_bytes(), salt.as_bytes(), 300_000, &mut o);
    o.iter().map(|b| format!("{:02x}", b)).collect()
}

fn load_cfg() -> Option<Cfg> {
    serde_json::from_str(&fs::read_to_string(p("config.json")).ok()?).ok()
}

fn save_cfg(c: &Cfg) {
    let f = p("config.json");
    let _ = fs::write(&f, serde_json::to_string(c).unwrap());
    #[cfg(windows)]
    sh("icacls", &[f.to_str().unwrap(), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&f, fs::Permissions::from_mode(0o600));
    }
}

// ---------- DNS ----------
fn reload() {
    let mt = fs::metadata(p("blocklist.txt")).and_then(|m| m.modified());
    let t = mt.ok().and_then(|m| m.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    if MT.swap(t, Ordering::Relaxed) != t {
        if let Ok(s) = fs::read_to_string(p("blocklist.txt")) {
            let mut set: HashSet<String> = s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            set.extend(BYPASS.iter().map(|s| s.to_string()));
            *BLOCK.write().unwrap() = Some(set);
        }
    }
}

fn is_blocked(name: &str) -> bool {
    let n = name.to_lowercase();
    let n = n.trim_end_matches('.');
    let parts: Vec<&str> = n.split('.').collect();
    let g = BLOCK.read().unwrap();
    for i in 0..parts.len().saturating_sub(1) {
        let d = parts[i..].join(".");
        if g.as_ref().map_or(false, |s| s.contains(&d)) || BYPASS.contains(&d.as_str()) {
            return true;
        }
    }
    KEYWORDS.iter().any(|k| n.contains(k))
}

fn parse(d: &[u8]) -> Option<(String, u16, usize)> {
    if d.len() < 17 {
        return None;
    }
    let (mut i, mut labels) = (12usize, Vec::new());
    while *d.get(i)? != 0 {
        let l = d[i] as usize;
        labels.push(String::from_utf8_lossy(d.get(i + 1..i + 1 + l)?).to_string());
        i += l + 1;
    }
    let end = i + 5;
    if d.len() < end {
        return None;
    }
    Some((labels.join("."), u16::from_be_bytes([d[i + 1], d[i + 2]]), end))
}

fn block_reply(d: &[u8], qt: u16, qend: usize, ip: [u8; 4]) -> Vec<u8> {
    let an = if qt == 1 { 1u8 } else { 0 };
    let mut r = vec![d[0], d[1], 0x81, 0x80, 0, 1, 0, an, 0, 0, 0, 0];
    r.extend_from_slice(&d[12..qend]);
    if an == 1 {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&ip);
    }
    r
}

fn handle(sock: Arc<UdpSocket>, d: Vec<u8>, addr: SocketAddr) {
    if let Some((name, qt, qend)) = parse(&d) {
        if name == "ping.penjaga.local" {
            let _ = sock.send_to(&block_reply(&d, qt, qend, [127, 0, 0, 1]), addr);
            return;
        }
        if is_blocked(&name) {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p("blocked.log")) {
                let _ = writeln!(f, "{} {} {}", now(), addr.ip(), name);
            }
            let _ = sock.send_to(&block_reply(&d, qt, qend, [0, 0, 0, 0]), addr);
            return;
        }
    }
    for up in UPSTREAM.iter() {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
            if s.send_to(&d, (*up, 53)).is_ok() {
                let mut buf = [0u8; 4096];
                if let Ok((n, _)) = s.recv_from(&mut buf) {
                    let _ = sock.send_to(&buf[..n], addr);
                    return;
                }
            }
        }
    }
}

fn alive() -> bool {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in "ping.penjaga.local".split('.') {
        q.push(l.len() as u8);
        q.extend(l.bytes());
    }
    q.extend([0, 0, 1, 0, 1]);
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = s.send_to(&q, "127.0.0.1:53");
    s.recv_from(&mut [0u8; 512]).is_ok()
}

fn count() -> usize {
    fs::read_to_string(p("blocked.log")).map(|s| s.lines().count()).unwrap_or(0)
}

// ---------- penegakan ----------
fn enforce_dns() {
    #[cfg(windows)]
    sh("powershell", &["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object Status -eq Up | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses 127.0.0.1 }"]);
    #[cfg(not(windows))]
    {
        let r = "/etc/resolv.conf";
        let cur = fs::read_to_string(r).unwrap_or_default();
        if cur.trim() != "nameserver 127.0.0.1" {
            if !cur.trim().is_empty() && !p("resolv.bak").exists() {
                let _ = fs::write(p("resolv.bak"), &cur);
            }
            sh("chattr", &["-i", r]);
            let _ = fs::remove_file(r);
            let _ = fs::write(r, "nameserver 127.0.0.1\n");
            sh("chattr", &["+i", r]);
        }
    }
}

fn restore_dns() {
    #[cfg(windows)]
    sh("powershell", &["-NoProfile", "-Command",
        "Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"]);
    #[cfg(not(windows))]
    {
        let r = "/etc/resolv.conf";
        sh("chattr", &["-i", r]);
        let _ = fs::remove_file(r);
        let _ = fs::write(r, fs::read_to_string(p("resolv.bak")).unwrap_or("nameserver 1.1.1.1\n".into()));
    }
}

#[cfg(not(windows))]
const RULES: [&[&str]; 5] = [
    &["-p", "udp", "--dport", "53", "-d", "127.0.0.0/8", "-j", "ACCEPT"],
    &["-p", "tcp", "--dport", "53", "-d", "127.0.0.0/8", "-j", "ACCEPT"],
    &["-p", "udp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "0", "-j", "REJECT"],
    &["-p", "tcp", "--dport", "53", "-m", "owner", "!", "--uid-owner", "0", "-j", "REJECT"],
    &["-p", "tcp", "--dport", "853", "-j", "REJECT"],
];

fn fw(add: bool) {
    #[cfg(not(windows))]
    for r in RULES.iter() {
        let with = |op: &'static str| {
            let mut a = vec![op, "OUTPUT"];
            a.extend_from_slice(r);
            a
        };
        let exists = sh("iptables", &with("-C"));
        if add && !exists {
            sh("iptables", &with("-A"));
        } else if !add && exists {
            sh("iptables", &with("-D"));
        }
    }
    #[cfg(windows)]
    {
        let ex = sh("netsh", &["advfirewall", "firewall", "show", "rule", "name=Penjaga-DoT"]);
        if add && !ex {
            sh("netsh", &["advfirewall", "firewall", "add", "rule", "name=Penjaga-DoT", "dir=out",
                "action=block", "protocol=TCP", "remoteport=853"]);
        } else if !add && ex {
            sh("netsh", &["advfirewall", "firewall", "delete", "rule", "name=Penjaga-DoT"]);
        }
    }
}

// ---------- layanan & penjaga-diri ----------
#[cfg(windows)]
fn service_ok() -> bool {
    sh("schtasks", &["/Query", "/TN", "Penjaga"])
}
#[cfg(not(windows))]
fn service_ok() -> bool {
    sh("systemctl", &["is-enabled", "penjaga"])
}

#[cfg(windows)]
fn setup_service() {
    let task = format!("\"{}\" run", BIN); // jalan tiap menit sebagai SYSTEM; instance ganda langsung keluar
    sh("schtasks", &["/Create", "/TN", "Penjaga", "/TR", &task, "/SC", "MINUTE", "/MO", "1",
        "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"]);
    let tray = format!("\"{}\" tray", BIN);
    sh("reg", &["add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Penjaga",
        "/t", "REG_SZ", "/d", &tray, "/f"]);
}
#[cfg(not(windows))]
fn setup_service() {
    let unit = format!("[Unit]\nDescription=Penjaga\nAfter=network.target\n[Service]\nExecStart={} run\nRestart=always\nRestartSec=2\n[Install]\nWantedBy=multi-user.target\n", BIN);
    let _ = fs::write("/etc/systemd/system/penjaga.service", unit);
    sh("systemctl", &["daemon-reload"]);
    sh("systemctl", &["enable", "penjaga"]);
}

/// Pulihkan salinan biner yang dihapus & layanan yang dicopot.
fn guard() {
    for (a, b) in [(BIN, BIN2), (BIN2, BIN)] {
        if !Path::new(a).exists() && Path::new(b).exists() {
            let _ = fs::create_dir_all(Path::new(a).parent().unwrap());
            let _ = fs::copy(b, a);
        }
    }
    if !service_ok() {
        setup_service();
    }
}

fn run() {
    let sock = match UdpSocket::bind("127.0.0.1:53") {
        Ok(s) => Arc::new(s),
        Err(_) => return, // sudah ada instance lain
    };
    reload();
    thread::spawn(|| {
        let mut t = 0u64;
        loop {
            if p("stop").exists() {
                std::process::exit(0);
            }
            if t % 20 == 0 {
                reload();
                guard();
                enforce_dns();
                fw(true);
            }
            t += 1;
            thread::sleep(Duration::from_secs(1));
        }
    });
    let mut buf = [0u8; 4096];
    loop {
        if let Ok((n, a)) = sock.recv_from(&mut buf) {
            let (s, d) = (sock.clone(), buf[..n].to_vec());
            thread::spawn(move || handle(s, d, a));
        }
    }
}

// ---------- tray (Windows) ----------
#[cfg(windows)]
fn tray() {
    use std::time::Instant;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    unsafe { windows_sys::Win32::System::Console::FreeConsole() };
    // Ikon dibuat lewat kode: lingkaran hijau berbingkai putih
    let mut px = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 {
        for x in 0..32 {
            let (dx, dy) = (x as f32 - 15.5, y as f32 - 15.5);
            let d = (dx * dx + dy * dy).sqrt();
            let c: [u8; 4] = if d > 15.0 { [0, 0, 0, 0] } else if d > 11.0 { [255, 255, 255, 255] } else { [30, 158, 106, 255] };
            px.extend(c);
        }
    }
    let icon = Icon::from_rgba(px, 32, 32).unwrap();

    let ev = EventLoopBuilder::new().build();
    let menu = Menu::new();
    let st = MenuItem::new("Status: memeriksa...", false, None);
    let cnt = MenuItem::new("Terblokir: 0", false, None);
    let open = MenuItem::new("Lihat log pemblokiran", true, None);
    let hint = MenuItem::new("Dilindungi. Lepas: penjaga uninstall (Admin)", false, None);
    let _ = menu.append(&st);
    let _ = menu.append(&cnt);
    let _ = menu.append(&open);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&hint);
    let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("Penjaga - filter internet").with_icon(icon).build().unwrap();
    let open_id = open.id().clone();

    ev.run(move |_, _, flow| {
        let _ = &tray;
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(5));
        if let Ok(e) = MenuEvent::receiver().try_recv() {
            if e.id == open_id {
                let _ = Command::new("notepad").arg(p("blocked.log")).spawn();
            }
        }
        st.set_text(if alive() { "Status: AKTIF" } else { "Status: MATI!" });
        cnt.set_text(format!("Terblokir: {}", count()));
    });
}
#[cfg(not(windows))]
fn tray() {
    println!("Ikon tray hanya tersedia di Windows (Linux berjalan sebagai layanan systemd).");
}

// ---------- perintah ----------
fn update_list() -> Result<usize, Box<dyn std::error::Error>> {
    let mut s = String::new();
    ureq::get(HOSTS_URL).timeout(Duration::from_secs(60)).call()?.into_reader().read_to_string(&mut s)?;
    let mut v: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split('#').next()?.split_whitespace().collect();
            (w.len() >= 2 && (w[0] == "0.0.0.0" || w[0] == "127.0.0.1") && !["localhost", "local", "0.0.0.0"].contains(&w[1]))
                .then(|| w[1].to_lowercase())
        })
        .collect();
    v.sort();
    v.dedup();
    fs::create_dir_all(HOME)?;
    fs::write(p("blocklist.txt"), v.join("\n"))?;
    Ok(v.len())
}

fn ask(q: &str) -> String {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn install() {
    need_root();
    let pw = rpassword::prompt_password("Buat password pelepasan (simpan di orang tepercaya): ").unwrap_or_default();
    if pw.len() < 6 || pw != rpassword::prompt_password("Ulangi password: ").unwrap_or_default() {
        eprintln!("Password tidak cocok / kurang dari 6 karakter.");
        return;
    }
    let delay: f64 = ask("Masa tunggu sebelum bisa dilepas, dalam jam [24]: ").parse().unwrap_or(24.0);

    let _ = fs::create_dir_all(HOME);
    #[cfg(windows)]
    sh("icacls", &[HOME, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"]);
    let _ = fs::remove_file(p("stop"));
    let me = std::env::current_exe().unwrap();
    for b in [BIN, BIN2] {
        let _ = fs::create_dir_all(Path::new(b).parent().unwrap());
        let _ = fs::copy(&me, b);
    }
    let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    save_cfg(&Cfg { hash: hashpw(&pw, &salt), salt, delay_h: delay, unlock_at: 0 });

    match update_list() {
        Ok(n) => println!("{n} domain masuk daftar blokir."),
        Err(e) => println!("Peringatan: gagal unduh daftar ({e}); memakai kata kunci + DNS hulu saja."),
    }
    setup_service();
    #[cfg(windows)]
    {
        sh("schtasks", &["/Run", "/TN", "Penjaga"]);
        let _ = Command::new(BIN).arg("tray").spawn();
    }
    #[cfg(not(windows))]
    sh("systemctl", &["start", "penjaga"]);
    println!("Terpasang. Filter aktif dan otomatis jalan tiap boot.");
}

fn status() {
    println!("Filter: {}", if alive() { "AKTIF" } else { "TIDAK berjalan" });
    println!("Percobaan terblokir: {}", count());
    if let Some(c) = load_cfg() {
        if c.unlock_at > 0 {
            let t = c.unlock_at as i64 - now() as i64;
            println!("Permintaan pelepasan: {}", if t > 0 { format!("sisa {:.1} jam", t as f64 / 3600.0) } else { "SIAP dilepas".into() });
        }
    }
}

fn cancel() {
    need_root();
    if let Some(mut c) = load_cfg() {
        c.unlock_at = 0;
        save_cfg(&c);
        println!("Permintaan pelepasan dibatalkan.");
    }
}

fn uninstall() {
    need_root();
    let Some(mut c) = load_cfg() else { return eprintln!("Konfigurasi tidak ditemukan.") };
    if hashpw(&rpassword::prompt_password("Password: ").unwrap_or_default(), &c.salt) != c.hash {
        return eprintln!("Password salah.");
    }
    if c.unlock_at == 0 {
        c.unlock_at = now() + (c.delay_h * 3600.0) as u64;
        save_cfg(&c);
        return println!("Permintaan dicatat. Jalankan lagi setelah {} jam untuk melepas.", c.delay_h);
    }
    if now() < c.unlock_at {
        return println!("Belum waktunya. Sisa {:.1} jam.", (c.unlock_at - now()) as f64 / 3600.0);
    }
    let _ = fs::write(p("stop"), "1"); // mesin berhenti sendiri dalam 1 detik
    #[cfg(windows)]
    {
        sh("schtasks", &["/End", "/TN", "Penjaga"]);
        sh("schtasks", &["/Delete", "/TN", "Penjaga", "/F"]);
        sh("reg", &["delete", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Penjaga", "/f"]);
        thread::sleep(Duration::from_secs(3));
        sh("taskkill", &["/F", "/IM", "penjaga.exe", "/FI", &format!("PID ne {}", std::process::id())]);
    }
    #[cfg(not(windows))]
    {
        sh("systemctl", &["disable", "--now", "penjaga"]);
        let _ = fs::remove_file("/etc/systemd/system/penjaga.service");
        thread::sleep(Duration::from_secs(3));
    }
    fw(false);
    restore_dns();
    let _ = fs::remove_dir_all(Path::new(BIN).parent().unwrap());
    let _ = fs::remove_dir_all(HOME);
    println!("Penjaga dilepas. DNS dikembalikan.");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("run") => run(),
        Some("tray") => tray(),
        Some("install") => install(),
        Some("status") => status(),
        Some("cancel") => cancel(),
        Some("uninstall") => uninstall(),
        Some("update-list") => {
            need_root();
            match update_list() {
                Ok(n) => println!("{n} domain diblokir."),
                Err(e) => println!("Gagal: {e}"),
            }
        }
        _ => println!("{USAGE}"),
    }
}
