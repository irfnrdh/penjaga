//! PENJAGA v2 - filter internet ketat, berjalan di background, sulit dimatikan.
//!
//! ARSITEKTUR
//!  * MESIN (`run`): jalan sebagai SYSTEM/root. Berisi server DNS (UDP+TCP :53), server kontrol
//!    (TCP 127.0.0.1:5380), dan "supervisor" yang menegakkan pengaturan tiap beberapa detik.
//!  * CLI: hanyalah klien tipis ke server kontrol. Verifikasi password dan penghitungan masa tunggu
//!    dilakukan OLEH MESIN, bukan lewat file/flag yang bisa dipalsukan (tidak ada backdoor `stop`).
//!  * TRAY (Windows): ikon di dekat jam, hanya menampilkan status.
//!  * GUARD: tugas kedua (Task Scheduler / systemd timer) yang saling menjaga dengan mesin.
//!
//! BATAS YANG JUJUR: siapa pun yang memegang hak Administrator/root penuh dan cukup ahli tetap bisa
//! mengalahkan perangkat lunak apa pun di mesinnya sendiri. Tujuan kode ini: membuat pembobolan
//! TIDAK bisa dilakukan secara impulsif (butuh password + menunggu berjam-jam) dan setiap
//! percobaan utak-atik dipulihkan serta dilaporkan ke pendamping lewat webhook.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// ======================================================================================
// KONSTANTA
// ======================================================================================

// Lokasi file. Windows: folder data hanya bisa diakses SYSTEM+Admin; biner utama di Program Files.
#[cfg(windows)]
const HOME: &str = r"C:\ProgramData\Penjaga";
#[cfg(windows)]
const BIN: &str = r"C:\Program Files\Penjaga\penjaga.exe";
#[cfg(windows)]
const BIN2: &str = r"C:\ProgramData\Penjaga\backup\penjaga.exe";
#[cfg(windows)]
const CFG2: &str = r"C:\Program Files\Penjaga\config.json";
#[cfg(windows)]
const RUN_KEY: &str = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(not(windows))]
const HOME: &str = "/opt/penjaga";
#[cfg(not(windows))]
const BIN: &str = "/usr/local/sbin/penjaga";
#[cfg(not(windows))]
const BIN2: &str = "/opt/penjaga/backup/penjaga";
#[cfg(not(windows))]
const CFG2: &str = "/usr/local/lib/penjaga/config.json";

/// Alamat server kontrol (hanya loopback).
const CTL: &str = "127.0.0.1:5380";

/// DNS hulu yang sudah memfilter konten dewasa/malware. Urutan = prioritas.
/// Firewall MENGECUALIKAN alamat-alamat ini, jadi hanya merekalah tujuan DNS yang boleh.
const UPSTREAM: [&str; 3] = ["1.1.1.3", "1.0.0.3", "185.228.168.168"];

const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts";

/// Kata kunci di nama domain. Sengaja tidak terlalu umum agar minim salah-blokir
/// (mis. "sex" dibuang karena memblokir "sussex"). Domain salah-blokir bisa di-`allow` (lihat CLI).
const KEYWORDS: &[&str] = &[
    "porn", "xxx", "bokep", "hentai", "xvideo", "xnxx", "redtube", "youporn", "xhamster", "ngentot",
    "memek", "togel", "judol", "judionline", "slotgacor", "slot88", "sbobet", "casino", "bandarq",
];

/// Domain pemutus filter (penyedia DoH/DoT + situs unduhan VPN). TIDAK bisa di-allow.
const BYPASS: &[&str] = &[
    "dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com", "family.cloudflare-dns.com", "one.one.one.one", "dns.quad9.net",
    "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
    "dns.adguard.com", "dns-family.adguard.com", "dns.nextdns.io", "doh.dns.sb",
    "doh.cleanbrowsing.org", "nordvpn.com", "protonvpn.com", "expressvpn.com", "windscribe.com",
    "tunnelbear.com", "hide.me", "psiphon.ca", "hidemyass.com",
];

/// "Canary domain": dijawab NXDOMAIN agar browser/OS MEMATIKAN DoH & Private Relay sendiri.
const CANARY: &[&str] = &["use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"];

/// IP resolver DoH terkenal. Port 443 ke sana diblokir agar DoH-via-IP tidak lolos.
const DOH_IPS: [&str; 12] = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "94.140.14.14", "94.140.15.15", "45.90.28.193", "45.90.30.193",
];

const MAX_INFLIGHT: usize = 256; // batas thread DNS bersamaan (anti-banjir)
const CACHE_TTL: u64 = 60; // detik
const CACHE_MAX: usize = 4000;

// ======================================================================================
// STATE GLOBAL
// ======================================================================================

/// Konfigurasi tetap. Disalin ke DUA lokasi dan DIPULIHKAN mesin bila diubah/dihapus.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Cfg {
    salt: String,
    hash: String,
    delay_h: f64,   // masa tunggu sebelum pelepasan boleh dikonfirmasi
    confirm_h: f64, // jendela konfirmasi setelah masa tunggu; lewat = permintaan hangus
    webhook: String, // URL notifikasi ke pendamping (boleh kosong)
}

/// State dinamis. Otoritatif di MEMORI mesin; file hanya cadangan untuk restart.
/// Semua penghitung memakai waktu MONOTON (Instant), bukan jam dinding, sehingga
/// memajukan jam komputer tidak mempercepat masa tunggu.
#[derive(Serialize, Deserialize, Default)]
struct State {
    requested: bool,
    waited: u64,   // detik masa tunggu yang sudah berlalu sejak permintaan
    window: u64,   // detik sejak masa tunggu selesai (jendela konfirmasi)
    fails: u32,    // salah password beruntun
    lock_left: u64, // sisa detik terkunci akibat salah password
    uptime: u64,   // total detik mesin hidup (jadwal allowlist tertunda)
    blocked: u64,  // total domain terblokir
    allow: Vec<String>,
    pending: Vec<(String, u64)>, // (domain, uptime saat berlaku)
    deny: Vec<String>,
}
impl State {
    const fn new() -> Self {
        State { requested: false, waited: 0, window: 0, fails: 0, lock_left: 0, uptime: 0, blocked: 0,
                allow: Vec::new(), pending: Vec::new(), deny: Vec::new() }
    }
}

static ST: Mutex<State> = Mutex::new(State::new());
static CFG: RwLock<Option<Cfg>> = RwLock::new(None);
static BLOCK: RwLock<Option<HashSet<String>>> = RwLock::new(None);
static CACHE: Mutex<Option<HashMap<(String, u16), (Instant, Vec<u8>)>>> = Mutex::new(None);
static MY_HASH: RwLock<String> = RwLock::new(String::new());
static MT: AtomicU64 = AtomicU64::new(0);
static LAST_TAMPER: AtomicU64 = AtomicU64::new(0);
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static DYING: AtomicBool = AtomicBool::new(false); // true saat teardown: hentikan semua penegakan

// Pengambil kunci yang tahan "poisoning" (thread lain panic tidak membuat mesin macet).
fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> { m.lock().unwrap_or_else(|e| e.into_inner()) }
fn rlock<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> { m.read().unwrap_or_else(|e| e.into_inner()) }
fn wlock<T>(m: &RwLock<T>) -> RwLockWriteGuard<'_, T> { m.write().unwrap_or_else(|e| e.into_inner()) }

// ======================================================================================
// UTILITAS
// ======================================================================================

fn p(name: &str) -> PathBuf { Path::new(HOME).join(name) }
fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

/// Siapkan perintah eksternal tanpa jendela (Windows).
fn cmd(prog: &str, args: &[&str]) -> Command {
    let mut c = Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    c
}
fn sh(prog: &str, args: &[&str]) -> bool {
    cmd(prog, args).output().map(|o| o.status.success()).unwrap_or(false)
}
fn sh_out(prog: &str, args: &[&str]) -> (bool, String) {
    match cmd(prog, args).output() {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned()),
        Err(_) => (false, String::new()),
    }
}
/// Varian untuk argumen bertipe String.
fn shv(prog: &str, args: Vec<String>) -> bool {
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    sh(prog, &a)
}

fn is_root() -> bool {
    #[cfg(windows)]
    return sh("net", &["session"]); // berhasil hanya bila Administrator
    #[cfg(not(windows))]
    return sh_out("id", &["-u"]).1.trim() == "0";
}
fn need_root() {
    if !is_root() {
        eprintln!("Jalankan sebagai Administrator / root.");
        std::process::exit(1);
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn unhex(s: &str) -> Option<String> {
    if s.len() % 2 != 0 { return None; }
    let mut v = Vec::new();
    for i in (0..s.len()).step_by(2) {
        v.push(u8::from_str_radix(s.get(i..i + 2)?, 16).ok()?);
    }
    String::from_utf8(v).ok()
}

/// PBKDF2-HMAC-SHA256, 300 ribu iterasi: memperlambat tebak-menebak password.
fn hashpw(pw: &str, salt: &str) -> String {
    let mut o = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(), salt.as_bytes(), 300_000, &mut o);
    hex(&o)
}

fn file_hash(path: &Path) -> Option<String> {
    Some(format!("{:x}", Sha256::digest(&fs::read(path).ok()?)))
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string())
}

/// Normalisasi & validasi nama domain masukan pengguna.
fn clean_domain(s: &str) -> Option<String> {
    let d = s.trim().trim_matches('.').to_lowercase();
    let ok = d.contains('.') && d.len() < 254 && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    ok.then_some(d)
}

/// Tulis file privat (hanya SYSTEM/Admin atau root yang boleh baca/tulis).
fn write_private(path: &Path, data: &str) {
    if let Some(dir) = path.parent() { let _ = fs::create_dir_all(dir); }
    let _ = fs::write(path, data);
    #[cfg(windows)]
    if let Some(s) = path.to_str() {
        sh("icacls", &[s, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

// ----- konfigurasi & state di disk -----

fn read_cfg_file(path: &Path) -> Option<Cfg> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}
fn read_cfg() -> Option<Cfg> {
    read_cfg_file(&p("config.json")).or_else(|| read_cfg_file(Path::new(CFG2)))
}
fn save_cfg(c: &Cfg) {
    let js = serde_json::to_string(c).unwrap();
    write_private(&p("config.json"), &js);
    write_private(Path::new(CFG2), &js); // salinan kedua di lokasi terlindungi lain
}
fn save_state() {
    if DYING.load(Ordering::SeqCst) { return; }
    let js = serde_json::to_string(&*lk(&ST)).unwrap_or_default();
    write_private(&p("state.json"), &js);
}

// ----- notifikasi ke pendamping -----

/// Kirim pesan ke webhook (mis. ntfy.sh / Telegram). Fire-and-forget; tanpa shell, jadi aman dari injeksi.
fn notify(msg: &str) {
    let Some(c) = rlock(&CFG).clone() else { return };
    if c.webhook.is_empty() { return; }
    let body = format!("[{}] {}", hostname(), msg);
    thread::spawn(move || { sh("curl", &["-fsS", "-m", "15", "-d", &body, &c.webhook]); });
}
/// Notifikasi tamper dibatasi 1 per 5 menit agar tidak membanjiri pendamping.
fn tamper(msg: &str) {
    let t = now();
    if t.saturating_sub(LAST_TAMPER.load(Ordering::Relaxed)) >= 300 {
        LAST_TAMPER.store(t, Ordering::Relaxed);
        notify(&format!("PERINGATAN: {msg}"));
    }
}

// ======================================================================================
// DNS: PARSING & PEMBUATAN PAKET
// ======================================================================================

/// Baca pertanyaan DNS. Mengembalikan (nama huruf kecil, tipe, offset akhir pertanyaan).
/// Paket tak valid -> None, dan pemanggil MENOLAK (tidak diteruskan = tidak fail-open).
fn parse(d: &[u8]) -> Option<(String, u16, usize)> {
    if d.len() < 17 || u16::from_be_bytes([d[4], d[5]]) != 1 { return None; } // harus tepat 1 pertanyaan
    let (mut i, mut total) = (12usize, 0usize);
    let mut labels: Vec<String> = Vec::new();
    loop {
        let l = *d.get(i)? as usize;
        if l == 0 { break; }
        if (l & 0xC0) != 0 { return None; } // pointer kompresi tidak sah di bagian pertanyaan
        total += l + 1;
        if total > 255 { return None; }
        labels.push(String::from_utf8_lossy(d.get(i + 1..i + 1 + l)?).to_lowercase());
        i += l + 1;
    }
    let end = i + 5; // 0-terminator + 2 byte tipe + 2 byte kelas
    if d.len() < end { return None; }
    Some((labels.join("."), u16::from_be_bytes([d[i + 1], d[i + 2]]), end))
}

/// Bangun balasan: header + pertanyaan asli + jawaban (nama dirujuk ke pertanyaan lewat pointer).
fn reply(d: &[u8], qend: usize, rcode: u8, ans: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let n = ans.len();
    let mut r = vec![d[0], d[1], 0x81, 0x80 | rcode, 0, 1, (n >> 8) as u8, n as u8, 0, 0, 0, 0];
    r.extend_from_slice(&d[12..qend]);
    for (t, data) in ans {
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend(t.to_be_bytes());
        r.extend([0, 1, 0, 0, 0, 60]); // kelas IN, TTL 60 detik
        r.extend((data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
    }
    r
}
/// Balasan galat tanpa bagian pertanyaan (SERVFAIL=2, FORMERR=1, NXDOMAIN=3, NOTIMP=4).
fn err_reply(d: &[u8], rcode: u8) -> Vec<u8> {
    vec![d[0], d[1], 0x81, 0x80 | rcode, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn build_query(id: [u8; 2], name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') { q.push(l.len() as u8); q.extend(l.bytes()); }
    q.push(0);
    q.extend(qtype.to_be_bytes());
    q.extend([0, 1]);
    q
}

/// Lewati satu nama DNS (label biasa atau pointer kompresi).
fn skip_name(d: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *d.get(i)?;
        if l == 0 { return Some(i + 1); }
        if (l & 0xC0) == 0xC0 { return Some(i + 2); }
        i += l as usize + 1;
    }
}
/// Ambil rdata semua jawaban bertipe `qtype` dari sebuah respons.
fn answers_of(resp: &[u8], qtype: u16) -> Option<Vec<(u16, Vec<u8>)>> {
    if resp.len() < 12 || (resp[3] & 0x0F) != 0 { return None; }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    let mut i = 12;
    for _ in 0..qd { i = skip_name(resp, i)? + 4; }
    let mut out = Vec::new();
    for _ in 0..an {
        i = skip_name(resp, i)?;
        let t = u16::from_be_bytes([*resp.get(i)?, *resp.get(i + 1)?]);
        let rl = u16::from_be_bytes([*resp.get(i + 8)?, *resp.get(i + 9)?]) as usize;
        let data = resp.get(i + 10..i + 10 + rl)?;
        if t == qtype { out.push((t, data.to_vec())); }
        i += 10 + rl;
    }
    Some(out)
}

// ======================================================================================
// DNS: KEPUTUSAN BLOKIR, SAFESEARCH, CACHE, FORWARD
// ======================================================================================

/// Muat ulang daftar blokir dari disk bila file berubah (dicek lewat waktu modifikasi).
fn reload() {
    let t = fs::metadata(p("blocklist.txt")).and_then(|m| m.modified()).ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    if MT.swap(t, Ordering::Relaxed) != t {
        if let Ok(s) = fs::read_to_string(p("blocklist.txt")) {
            *wlock(&BLOCK) = Some(s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect());
        }
    }
}

/// Urutan prioritas per sufiks domain (dari yang paling spesifik):
/// BYPASS (selalu blokir) > deny pengguna > allow pengguna > daftar > kata kunci.
fn is_blocked(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    let st = lk(&ST);
    let list = rlock(&BLOCK);
    let mut hit = false;
    for i in 0..parts.len().saturating_sub(1) {
        let d = parts[i..].join(".");
        if BYPASS.contains(&d.as_str()) || st.deny.iter().any(|x| *x == d) { return true; }
        if st.allow.iter().any(|x| *x == d) { return false; }
        if list.as_ref().map_or(false, |s| s.contains(&d)) { hit = true; }
    }
    hit || KEYWORDS.iter().any(|k| name.contains(k))
}

fn log_block(ip: IpAddr, name: &str) {
    lk(&ST).blocked += 1;
    let f = p("blocked.log");
    // rotasi: log tidak tumbuh tanpa batas
    if fs::metadata(&f).map(|m| m.len() > 5_000_000).unwrap_or(false) {
        let _ = fs::rename(&f, p("blocked.log.1"));
    }
    if let Ok(mut h) = fs::OpenOptions::new().create(true).append(true).open(&f) {
        let _ = writeln!(h, "{} {} {}", now(), ip, name);
    }
}

/// SafeSearch paksa lewat DNS: Google/Bing/YouTube dialihkan ke host "aman" resmi mereka.
fn safe_target(name: &str) -> Option<&'static str> {
    match name {
        "google.com" | "www.google.com" | "google.co.id" | "www.google.co.id" => Some("forcesafesearch.google.com"),
        "bing.com" | "www.bing.com" => Some("strict.bing.com"),
        "youtube.com" | "www.youtube.com" | "m.youtube.com" | "youtubei.googleapis.com"
        | "youtube.googleapis.com" | "www.youtube-nocookie.com" => Some("restrict.youtube.com"),
        _ => None,
    }
}

/// Balapan UDP ke hulu: kirim ke 2 server sekaligus, server ke-3 setelah 700ms.
/// Hanya balasan dari IP hulu dengan ID cocok yang diterima (anti-spoof sederhana).
fn upstream_udp(q: &[u8]) -> Option<Vec<u8>> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
    let start = Instant::now();
    let (mut sent, mut buf) = (0usize, [0u8; 4096]);
    while start.elapsed() < Duration::from_secs(3) {
        let want = if start.elapsed() < Duration::from_millis(700) { 2 } else { 3 };
        while sent < want { let _ = s.send_to(q, (UPSTREAM[sent], 53)); sent += 1; }
        if let Ok((n, from)) = s.recv_from(&mut buf) {
            if n >= 12 && buf[..2] == q[..2] && UPSTREAM.iter().any(|u| from.ip().to_string() == *u) {
                return Some(buf[..n].to_vec());
            }
        }
    }
    None
}
/// Cadangan lewat TCP (dipakai bila respons UDP terpotong atau UDP gagal).
fn upstream_tcp(q: &[u8]) -> Option<Vec<u8>> {
    for up in UPSTREAM {
        let addr: SocketAddr = format!("{up}:53").parse().ok()?;
        let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let mut m = (q.len() as u16).to_be_bytes().to_vec();
        m.extend_from_slice(q);
        let mut l = [0u8; 2];
        if s.write_all(&m).is_err() || s.read_exact(&mut l).is_err() { continue; }
        let mut buf = vec![0u8; u16::from_be_bytes(l) as usize];
        if s.read_exact(&mut buf).is_ok() { return Some(buf); }
    }
    None
}
fn forward(q: &[u8]) -> Option<Vec<u8>> {
    let udp = upstream_udp(q);
    if let Some(r) = &udp {
        if (r[2] & 0x02) == 0 { return udp; } // bit TC=0: respons lengkap
    }
    upstream_tcp(q).or(udp)
}

fn cache_put(key: (String, u16), r: &[u8]) {
    // hanya NOERROR/NXDOMAIN yang tidak terpotong
    if r.len() < 12 || (r[2] & 0x02) != 0 || !matches!(r[3] & 0x0F, 0 | 3) { return; }
    let mut c = lk(&CACHE);
    let m = c.get_or_insert_with(HashMap::new);
    if m.len() >= CACHE_MAX { m.clear(); }
    m.insert(key, (Instant::now() + Duration::from_secs(CACHE_TTL), r.to_vec()));
}

/// OTAK DNS: dari satu query menghasilkan satu jawaban. None = abaikan paket.
fn answer(d: &[u8], from: IpAddr) -> Option<Vec<u8>> {
    if d.len() < 12 || (d[2] & 0x80) != 0 { return None; } // bukan query
    if (d[2] & 0x78) != 0 { return Some(err_reply(d, 4)); } // opcode bukan QUERY -> NOTIMP
    // Paket cacat DITOLAK (FORMERR), tidak diteruskan ke hulu: tidak fail-open.
    let Some((name, qt, qend)) = parse(d) else { return Some(err_reply(d, 1)) };

    if CANARY.contains(&name.as_str()) { return Some(reply(d, qend, 3, &[])); } // NXDOMAIN
    if is_blocked(&name) {
        log_block(from, &name);
        // A -> 0.0.0.0 ; tipe lain (AAAA, HTTPS) -> kosong, sehingga klien jatuh ke 0.0.0.0
        return Some(if qt == 1 { reply(d, qend, 0, &[(1, vec![0, 0, 0, 0])]) } else { reply(d, qend, 0, &[]) });
    }
    if let Some(t) = safe_target(&name) {
        if qt != 1 && qt != 28 { return Some(reply(d, qend, 0, &[])); } // matikan HTTPS/ECH record di sini
        let q = build_query([d[0], d[1]], t, qt);
        return Some(match forward(&q).and_then(|r| answers_of(&r, qt)) {
            Some(a) => reply(d, qend, 0, &a),
            None => err_reply(d, 2),
        });
    }
    let key = (name, qt);
    if let Some(m) = lk(&CACHE).as_ref() {
        if let Some((exp, resp)) = m.get(&key) {
            if *exp > Instant::now() {
                let mut r = resp.clone();
                r[0] = d[0]; r[1] = d[1]; // pakai ID query yang sekarang
                return Some(r);
            }
        }
    }
    match forward(d) {
        Some(r) => { cache_put(key, &r); Some(r) }
        None => Some(err_reply(d, 2)), // SERVFAIL
    }
}

// ======================================================================================
// SERVER DNS (UDP + TCP) DENGAN PEMBATAS THREAD
// ======================================================================================

struct Slot;
impl Drop for Slot { fn drop(&mut self) { INFLIGHT.fetch_sub(1, Ordering::SeqCst); } }

/// Jalankan tugas di thread baru, maksimum MAX_INFLIGHT bersamaan (sisanya dibuang: anti-banjir).
/// Panic di dalam tugas ditangkap sehingga mesin tidak ikut mati.
fn spawn_limited<F: FnOnce() + Send + 'static>(f: F) {
    if INFLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_INFLIGHT {
        INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let r = thread::Builder::new().stack_size(256 * 1024).spawn(move || {
        let _slot = Slot;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    });
    if r.is_err() { INFLIGHT.fetch_sub(1, Ordering::SeqCst); }
}

fn udp_loop(sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, a)) = sock.recv_from(&mut buf) else {
            thread::sleep(Duration::from_millis(10)); // mis. WSAECONNRESET di Windows
            continue;
        };
        let (s, d) = (sock.clone(), buf[..n].to_vec());
        spawn_limited(move || { if let Some(r) = answer(&d, a.ip()) { let _ = s.send_to(&r, a); } });
    }
}

fn tcp_loop(l: TcpListener) {
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        spawn_limited(move || {
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let ip = s.peer_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([127, 0, 0, 1]));
            loop {
                let mut l = [0u8; 2];
                if s.read_exact(&mut l).is_err() { break; }
                let mut b = vec![0u8; u16::from_be_bytes(l) as usize];
                if s.read_exact(&mut b).is_err() { break; }
                let Some(r) = answer(&b, ip) else { break };
                let mut m = (r.len() as u16).to_be_bytes().to_vec();
                m.extend(r);
                if s.write_all(&m).is_err() { break; }
            }
        });
    }
}

// ======================================================================================
// SERVER KONTROL: password diverifikasi OLEH MESIN (bukan lewat file flag)
// ======================================================================================

/// Verifikasi password dengan pembatasan percobaan: 5 salah -> terkunci 15 menit, lalu berlipat ganda (maks 24 jam).
fn check_pw(pw: &str) -> Result<(), String> {
    let cfg = rlock(&CFG).clone().ok_or("ERR nocfg")?;
    if lk(&ST).lock_left > 0 { return Err(format!("LOCKED {}", lk(&ST).lock_left)); }
    let ok = hashpw(pw, &cfg.salt) == cfg.hash; // dihitung SEBELUM mengunci ST (PBKDF2 lambat)
    let mut st = lk(&ST);
    if ok { st.fails = 0; return Ok(()); }
    st.fails += 1;
    if st.fails >= 5 { st.lock_left = (900u64 << (st.fails - 5).min(6)).min(86_400); }
    let f = st.fails;
    drop(st);
    notify(&format!("Password pelepasan salah ({f}x berturut-turut)"));
    Err("BADPW".into())
}

fn reset_request() {
    { let mut st = lk(&ST); st.requested = false; st.waited = 0; st.window = 0; }
    save_state();
}

fn ctl_cmd(line: &str) -> String {
    let mut w = line.split_whitespace();
    match w.next().unwrap_or("") {
        "STATUS" => {
            let ds = rlock(&CFG).as_ref().map(|c| (c.delay_h * 3600.0) as u64).unwrap_or(0);
            let st = lk(&ST);
            format!("ACTIVE blocked={} req={} remain={} lock={}", st.blocked, st.requested as u8, ds.saturating_sub(st.waited), st.lock_left)
        }
        // Membatalkan permintaan pelepasan hanya membuat sistem LEBIH ketat -> tanpa password.
        "CANCEL" => { reset_request(); "OK".into() }
        // Menambah blokir juga tidak butuh password (asimetris: memperketat selalu mudah).
        "BLOCK" => match w.next().and_then(clean_domain) {
            Some(d) => { lk(&ST).deny.push(d); save_state(); "OK".into() }
            None => "ERR domain".into(),
        },
        "UPDATE" => { thread::spawn(|| { let _ = update_list(); }); "OK".into() }
        // Membuka blokir butuh password DAN baru berlaku setelah masa tunggu yang sama.
        "ALLOW" => {
            let (Some(pw), Some(dom)) = (w.next().and_then(unhex), w.next().and_then(clean_domain)) else { return "ERR".into() };
            if let Err(e) = check_pw(&pw) { return e; }
            let ds = rlock(&CFG).as_ref().map(|c| (c.delay_h * 3600.0) as u64).unwrap_or(86_400);
            { let mut st = lk(&ST); let at = st.uptime + ds; st.pending.push((dom.clone(), at)); }
            save_state();
            notify(&format!("Permintaan membuka blokir: {dom}"));
            format!("OK {ds}")
        }
        // Satu perintah, tiga fase: ajukan -> tunggu -> konfirmasi (diputuskan mesin).
        "UNINSTALL" => {
            let Some(pw) = w.next().and_then(unhex) else { return "ERR".into() };
            if let Err(e) = check_pw(&pw) { return e; }
            let ds = rlock(&CFG).as_ref().map(|c| (c.delay_h * 3600.0) as u64).unwrap_or(86_400);
            let mut st = lk(&ST);
            if !st.requested {
                st.requested = true; st.waited = 0; st.window = 0;
                drop(st);
                save_state();
                notify("Permintaan PELEPASAN Penjaga diajukan (password benar). Masa tunggu dimulai.");
                return format!("REQ {ds}");
            }
            if st.waited < ds { return format!("WAIT {}", ds - st.waited); }
            drop(st);
            notify("Pelepasan Penjaga DIKONFIRMASI. Penjaga dilepas.");
            thread::spawn(|| { thread::sleep(Duration::from_secs(1)); teardown(); });
            "DONE".into()
        }
        _ => "ERR".into(),
    }
}

fn ctl_loop(l: TcpListener) {
    for s in l.incoming() {
        let Ok(mut s) = s else { continue };
        if !s.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false) { continue; }
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let mut line = String::new();
        if BufReader::new(&s).take(2048).read_line(&mut line).is_err() { continue; }
        let r = ctl_cmd(line.trim());
        let _ = writeln!(s, "{r}");
    }
}

/// Klien kontrol (dipakai CLI dan tray).
fn ctl(line: &str) -> Option<String> {
    let a: SocketAddr = CTL.parse().ok()?;
    let mut s = TcpStream::connect_timeout(&a, Duration::from_millis(800)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(15))).ok()?;
    writeln!(s, "{line}").ok()?;
    let mut r = String::new();
    BufReader::new(s).read_line(&mut r).ok()?;
    Some(r.trim().to_string())
}

// ======================================================================================
// PENEGAKAN: DNS SISTEM, FIREWALL, KEBIJAKAN BROWSER
// ======================================================================================

/// Paksa semua adapter memakai filter lokal.
fn enforce_dns() {
    #[cfg(windows)]
    sh("powershell", &["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object Status -eq Up | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses 127.0.0.1 }"]);
    #[cfg(not(windows))]
    {
        let r = "/etc/resolv.conf";
        let cur = fs::read_to_string(r).unwrap_or_default();
        if cur.trim() != "nameserver 127.0.0.1" {
            if !cur.trim().is_empty() && !p("resolv.bak").exists() { let _ = fs::write(p("resolv.bak"), &cur); }
            sh("chattr", &["-i", r]);
            let _ = fs::remove_file(r);
            let _ = fs::write(r, "nameserver 127.0.0.1\n");
            sh("chattr", &["+i", r]); // immutable: NetworkManager/pengguna biasa tak bisa menimpa
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
        let _ = fs::write(r, fs::read_to_string(p("resolv.bak")).unwrap_or_else(|_| "nameserver 1.1.1.1\n".into()));
    }
}

// ----- util rentang IP (untuk aturan firewall Windows) -----
fn ip2u(s: &str) -> Option<u32> {
    let v: Option<Vec<u32>> = s.split('.').map(|x| x.parse::<u32>().ok().filter(|n| *n < 256)).collect();
    let v = v?;
    if v.len() != 4 { return None; }
    Some(v[0] << 24 | v[1] << 16 | v[2] << 8 | v[3])
}
fn u2ip(n: u32) -> String { format!("{}.{}.{}.{}", n >> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255) }
/// Kebalikan himpunan rentang: dipakai karena firewall Windows "blokir semua KECUALI X"
/// harus ditulis sebagai daftar rentang di luar X.
fn complement(ex: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut v = ex.to_vec();
    v.sort();
    let (mut out, mut next) = (Vec::new(), 0u64);
    for (a, b) in v {
        if (a as u64) > next { out.push((next as u32, a - 1)); }
        next = next.max(b as u64 + 1);
    }
    if next <= u32::MAX as u64 { out.push((next as u32, u32::MAX)); }
    out
}

/// Firewall: (1) DNS (port 53) hanya boleh ke loopback & server hulu, IPv4 maupun IPv6;
/// (2) DoT (853) diblokir; (3) DoH-via-IP (443 ke resolver terkenal) diblokir.
/// Windows: aturan netsh. Linux: chain khusus PENJAGA yang dibangun ulang bila isinya berubah.
fn fw(add: bool) {
    #[cfg(windows)]
    {
        let mut ex = vec![(ip2u("127.0.0.0").unwrap(), ip2u("127.255.255.255").unwrap())];
        ex.extend(UPSTREAM.iter().filter_map(|u| ip2u(u)).map(|n| (n, n)));
        let ip4 = complement(&ex).iter().map(|(a, b)| format!("{}-{}", u2ip(*a), u2ip(*b))).collect::<Vec<_>>().join(",");
        let doh = DOH_IPS.join(",");
        let v6 = "2000::/3,fe80::/10,fc00::/7".to_string();
        let rules = [
            ("Penjaga-DNS4-UDP", "UDP", "53", ip4.clone()), ("Penjaga-DNS4-TCP", "TCP", "53", ip4),
            ("Penjaga-DNS6-UDP", "UDP", "53", v6.clone()), ("Penjaga-DNS6-TCP", "TCP", "53", v6),
            ("Penjaga-DoT", "TCP", "853", "any".to_string()),
            ("Penjaga-DoH-TCP", "TCP", "443", doh.clone()), ("Penjaga-DoH-UDP", "UDP", "443", doh),
        ];
        for (name, proto, port, ip) in rules {
            let exists = sh("netsh", &["advfirewall", "firewall", "show", "rule", &format!("name={name}")]);
            if add && !exists {
                shv("netsh", ["advfirewall", "firewall", "add", "rule"].iter().map(|s| s.to_string())
                    .chain([format!("name={name}"), "dir=out".into(), "action=block".into(), "enable=yes".into(),
                            format!("protocol={proto}"), format!("remoteport={port}"), format!("remoteip={ip}")])
                    .collect());
            } else if !add && exists {
                sh("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={name}")]);
            }
        }
        // Admin sering "mematikan firewall" untuk membobol: nyalakan lagi.
        if add { sh("netsh", &["advfirewall", "set", "allprofiles", "state", "on"]); }
    }
    #[cfg(not(windows))]
    {
        let mut v4: Vec<String> = Vec::new();
        for proto in ["udp", "tcp"] {
            v4.push(format!("-p {proto} --dport 53 -d 127.0.0.0/8 -j ACCEPT"));
            for u in UPSTREAM { v4.push(format!("-p {proto} --dport 53 -d {u} -j ACCEPT")); }
            v4.push(format!("-p {proto} --dport 53 -j REJECT"));
        }
        v4.push("-p tcp --dport 853 -j REJECT".into());
        for ip in DOH_IPS { for proto in ["tcp", "udp"] { v4.push(format!("-p {proto} --dport 443 -d {ip} -j REJECT")); } }
        let v6: Vec<String> = vec![
            "-p udp --dport 53 -d ::1 -j ACCEPT".into(), "-p tcp --dport 53 -d ::1 -j ACCEPT".into(),
            "-p udp --dport 53 -j REJECT".into(), "-p tcp --dport 53 -j REJECT".into(), "-p tcp --dport 853 -j REJECT".into(),
        ];
        for (bin, rules) in [("iptables", v4), ("ip6tables", v6)] {
            if add {
                sh(bin, &["-N", "PENJAGA"]); // abaikan bila sudah ada
                if !sh(bin, &["-C", "OUTPUT", "-j", "PENJAGA"]) { sh(bin, &["-I", "OUTPUT", "1", "-j", "PENJAGA"]); }
                // isi chain tidak sesuai (diubah/ditambah/dikurangi) -> bangun ulang berurutan
                if sh_out(bin, &["-S", "PENJAGA"]).1.lines().count() != rules.len() + 1 {
                    sh(bin, &["-F", "PENJAGA"]);
                    for r in &rules {
                        let mut a = vec!["-A", "PENJAGA"];
                        a.extend(r.split_whitespace());
                        sh(bin, &a);
                    }
                }
            } else {
                sh(bin, &["-D", "OUTPUT", "-j", "PENJAGA"]);
                sh(bin, &["-F", "PENJAGA"]);
                sh(bin, &["-X", "PENJAGA"]);
            }
        }
    }
}

/// Kebijakan browser: matikan DoH/Secure DNS, paksa SafeSearch & YouTube Restricted,
/// matikan Smart Multi-Homed Name Resolution (kebocoran DNS Windows).
#[cfg(windows)]
const POL: &[(&str, &str, &str, &str)] = &[
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceGoogleSafeSearch", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceYouTubeRestrict", "REG_DWORD", "2"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceGoogleSafeSearch", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceBingSafeSearch", "REG_DWORD", "2"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceYouTubeRestrict", "REG_DWORD", "2"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DisableSmartNameResolution", "REG_DWORD", "1"),
];

fn policies(add: bool) {
    #[cfg(windows)]
    for (key, name, ty, data) in POL {
        if add { sh("reg", &["add", key, "/v", name, "/t", ty, "/d", data, "/f"]); }
        else { sh("reg", &["delete", key, "/v", name, "/f"]); }
    }
    #[cfg(not(windows))]
    {
        let chrome = r#"{"DnsOverHttpsMode":"off","ForceGoogleSafeSearch":true,"ForceYouTubeRestrict":2,"ForceBingSafeSearch":2}"#;
        let ff = r#"{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}"#;
        let mut files: Vec<(&str, &str)> = vec![
            ("/etc/opt/chrome/policies/managed/penjaga.json", chrome), ("/etc/chromium/policies/managed/penjaga.json", chrome),
            ("/etc/brave/policies/managed/penjaga.json", chrome), ("/etc/opt/edge/policies/managed/penjaga.json", chrome),
            ("/etc/firefox/policies/policies.json", ff),
        ];
        if Path::new("/usr/lib/firefox").exists() { files.push(("/usr/lib/firefox/distribution/policies.json", ff)); }
        for (f, c) in files {
            if add {
                if fs::read_to_string(f).ok().as_deref() != Some(c) {
                    if let Some(d) = Path::new(f).parent() { let _ = fs::create_dir_all(d); }
                    let _ = fs::write(f, c);
                }
            } else { let _ = fs::remove_file(f); }
        }
    }
}

// ======================================================================================
// LAYANAN, PENJAGA-DIRI (GUARD), INTEGRITAS
// ======================================================================================

#[cfg(windows)]
fn utf16(s: &str) -> Vec<u8> {
    let mut b = vec![0xFF, 0xFE]; // BOM UTF-16LE: format yang diminta schtasks /XML
    for u in s.encode_utf16() { b.extend(u.to_le_bytes()); }
    b
}
/// XML tugas: jalan sebagai SYSTEM, saat boot + berulang tiap menit, TETAP jalan di baterai,
/// tanpa batas waktu eksekusi, mulai ulang bila gagal. (schtasks biasa menghentikan task di baterai.)
#[cfg(windows)]
fn task_xml(args: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers>
<BootTrigger><Enabled>true</Enabled></BootTrigger>
<TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2000-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>
</Triggers>
<Principals><Principal id="A"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><AllowHardTerminate>false</AllowHardTerminate><Enabled>true</Enabled></Settings>
<Actions Context="A"><Exec><Command>{BIN}</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>"#)
}

#[cfg(windows)]
fn setup_service() -> bool {
    let mut ok = true;
    // Dua tugas yang saling menjaga: "Penjaga" (mesin) dan "PenjagaGuard" (pemulih).
    for (name, args) in [("Penjaga", "run"), ("PenjagaGuard", "guard-once")] {
        let f = p(&format!("{name}.xml"));
        let _ = fs::write(&f, utf16(&task_xml(args)));
        ok &= sh("schtasks", &["/Create", "/TN", name, "/XML", f.to_str().unwrap(), "/F"]);
    }
    ok & sh("reg", &["add", RUN_KEY, "/v", "Penjaga", "/t", "REG_SZ", "/d", &format!("\"{BIN}\" tray"), "/f"])
}
/// Bukan sekadar "ada": ISI tugas diperiksa (perintah, SYSTEM, pengulangan) agar tidak bisa dialihkan.
#[cfg(windows)]
fn service_ok() -> bool {
    let (a, x) = sh_out("schtasks", &["/Query", "/TN", "Penjaga", "/XML"]);
    a && x.contains(BIN) && x.contains("PT1M") && x.contains("S-1-5-18") && sh("schtasks", &["/Query", "/TN", "PenjagaGuard"])
}

#[cfg(not(windows))]
fn units() -> Vec<(&'static str, String)> {
    vec![
        ("/etc/systemd/system/penjaga.service", format!("[Unit]\nDescription=Penjaga filter\nAfter=network.target\n[Service]\nExecStart={BIN} run\nRestart=always\nRestartSec=2\nKillMode=process\n[Install]\nWantedBy=multi-user.target\n")),
        ("/etc/systemd/system/penjaga-guard.service", format!("[Unit]\nDescription=Penjaga guard\n[Service]\nType=oneshot\nExecStart={BIN} guard-once\n")),
        ("/etc/systemd/system/penjaga-guard.timer", "[Unit]\nDescription=Penjaga guard timer\n[Timer]\nOnBootSec=20\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n".to_string()),
    ]
}
#[cfg(not(windows))]
fn setup_service() -> bool {
    let (mut ok, mut changed) = (true, false);
    for (f, c) in units() {
        if fs::read_to_string(f).ok().as_deref() != Some(c.as_str()) { ok &= fs::write(f, &c).is_ok(); changed = true; }
    }
    if changed { sh("systemctl", &["daemon-reload"]); }
    ok & sh("systemctl", &["enable", "penjaga.service"]) & sh("systemctl", &["enable", "--now", "penjaga-guard.timer"])
}
#[cfg(not(windows))]
fn service_ok() -> bool {
    units().iter().all(|(f, c)| fs::read_to_string(f).ok().as_deref() == Some(c.as_str()))
        && sh("systemctl", &["is-enabled", "penjaga.service"]) && sh("systemctl", &["is-enabled", "penjaga-guard.timer"])
}

/// Pastikan DUA salinan biner utuh. Yang hilang/berbeda hash dipulihkan dari salinan yang cocok
/// dengan hash biner yang sedang berjalan.
fn ensure_copies() {
    let mine = rlock(&MY_HASH).clone();
    if mine.is_empty() { return; }
    let mut srcs = vec![PathBuf::from(BIN), PathBuf::from(BIN2)];
    if let Ok(m) = std::env::current_exe() { srcs.push(m); }
    for dst in [BIN, BIN2] {
        if file_hash(Path::new(dst)).as_deref() == Some(mine.as_str()) { continue; }
        for s in &srcs {
            if s.as_path() != Path::new(dst) && file_hash(s).as_deref() == Some(mine.as_str()) {
                if let Some(d) = Path::new(dst).parent() { let _ = fs::create_dir_all(d); }
                if fs::copy(s, dst).is_ok() { tamper(&format!("biner {dst} hilang/berubah, dipulihkan")); break; }
            }
        }
    }
}

/// Pemulih utama: salinan biner + layanan/tugas.
fn guard() {
    if DYING.load(Ordering::SeqCst) { return; }
    ensure_copies();
    if !service_ok() {
        tamper("layanan/tugas Penjaga dicopot atau diubah, dipulihkan");
        setup_service();
    }
}

/// Konfigurasi dijaga: bila file diubah/dihapus, ditulis ulang dari salinan di memori.
fn cfg_guard() {
    let Some(mem) = rlock(&CFG).clone() else { return };
    let same = |f: &Path| read_cfg_file(f).map_or(false, |c| c == mem);
    if !same(&p("config.json")) || !same(Path::new(CFG2)) {
        save_cfg(&mem);
        tamper("file konfigurasi diubah/dihapus, dipulihkan");
    }
}

/// Dipanggil tugas kedua (guard). Jika mesin mati, nyalakan.
fn guard_once() {
    if let Some(h) = std::env::current_exe().ok().and_then(|m| file_hash(&m)) { *wlock(&MY_HASH) = h; }
    guard();
    if ctl("STATUS").is_none() {
        #[cfg(windows)]
        sh("schtasks", &["/Run", "/TN", "Penjaga"]);
        #[cfg(not(windows))]
        sh("systemctl", &["start", "penjaga.service"]);
    }
}

// ======================================================================================
// DAFTAR BLOKIR
// ======================================================================================

/// Unduh daftar via curl, validasi (minimal 1000 domain) lalu ganti atomik. Gagal = daftar lama tetap.
fn update_list() -> Result<usize, String> {
    let tmp = p("blocklist.tmp");
    if !sh("curl", &["-fsSL", "-m", "120", "-o", tmp.to_str().unwrap(), HOSTS_URL]) {
        return Err("curl gagal mengunduh".into());
    }
    let s = fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
    let mut v: Vec<String> = s.lines().filter_map(|l| {
        let w: Vec<&str> = l.split('#').next()?.split_whitespace().collect();
        (w.len() >= 2 && (w[0] == "0.0.0.0" || w[0] == "127.0.0.1") && !["localhost", "local", "0.0.0.0"].contains(&w[1]))
            .then(|| w[1].to_lowercase())
    }).collect();
    v.sort();
    v.dedup();
    if v.len() < 1000 { return Err("daftar terunduh tidak valid (terlalu kecil)".into()); }
    fs::write(&tmp, v.join("\n")).map_err(|e| e.to_string())?;
    fs::rename(&tmp, p("blocklist.txt")).map_err(|e| e.to_string())?;
    reload();
    Ok(v.len())
}

// ======================================================================================
// MESIN: run() + supervisor
// ======================================================================================

fn run() {
    // Instans tunggal: bila port 53 sudah dipakai, berarti mesin lain sudah jalan.
    let Ok(udp) = UdpSocket::bind("127.0.0.1:53") else { return };
    let Ok(tcp) = TcpListener::bind("127.0.0.1:53") else { return };
    let Ok(ctl_l) = TcpListener::bind(CTL) else { return };

    if let Some(h) = std::env::current_exe().ok().and_then(|m| file_hash(&m)) { *wlock(&MY_HASH) = h; }
    // Muat konfigurasi. Bila hilang total: kunci permanen (password acak tak diketahui) + lapor.
    let cfg = read_cfg().unwrap_or_else(|| {
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let c = Cfg { salt, hash: hex(&rand::random::<[u8; 32]>()), delay_h: 24.0, confirm_h: 6.0, webhook: String::new() };
        save_cfg(&c);
        c
    });
    *wlock(&CFG) = Some(cfg);
    if let Some(s) = fs::read_to_string(p("state.json")).ok().and_then(|s| serde_json::from_str::<State>(&s).ok()) { *lk(&ST) = s; }
    reload();
    notify("Penjaga AKTIF (mesin dimulai)");

    let udp = Arc::new(udp);
    thread::spawn(move || udp_loop(udp));
    thread::spawn(move || tcp_loop(tcp));
    thread::spawn(move || ctl_loop(ctl_l));
    supervise();
}

/// Supervisor: hitung waktu monoton, tegakkan pengaturan, jadwalkan tugas harian.
fn supervise() -> ! {
    let (mut last, mut wall, mut t) = (Instant::now(), now(), 0u64);
    // Daftar belum ada / sudah basi -> unduh di latar belakang.
    let stale = fs::metadata(p("blocklist.txt")).and_then(|m| m.modified()).ok()
        .and_then(|m| m.elapsed().ok()).map_or(true, |e| e > Duration::from_secs(7 * 86_400));
    if stale { thread::spawn(|| { let _ = update_list(); }); }

    loop {
        thread::sleep(Duration::from_secs(1));
        if DYING.load(Ordering::SeqCst) { continue; }
        let dt = last.elapsed().as_secs().clamp(1, 5);
        last = Instant::now();
        t += 1;

        // Deteksi lompatan jam dinding (ubah jam / sleep panjang) -> hanya dilaporkan.
        // Masa tunggu TIDAK terpengaruh karena memakai penghitung monoton di bawah.
        let w = now();
        if w.abs_diff(wall) > 300 { tamper("jam sistem melompat (diubah atau perangkat tidur lama)"); }
        wall = w;

        {
            let cfg = rlock(&CFG).clone();
            let mut st = lk(&ST);
            st.uptime += dt;
            st.lock_left = st.lock_left.saturating_sub(dt);
            if let (Some(c), true) = (&cfg, st.requested) {
                let (ds, cs) = ((c.delay_h * 3600.0) as u64, (c.confirm_h * 3600.0) as u64);
                if st.waited < ds { st.waited = (st.waited + dt).min(ds); }
                else {
                    st.window += dt;
                    if st.window > cs { st.requested = false; st.waited = 0; st.window = 0; } // jendela konfirmasi habis
                }
            }
            // Allowlist tertunda yang sudah jatuh tempo menjadi aktif.
            let up = st.uptime;
            let mut due = Vec::new();
            st.pending.retain(|(d, at)| if *at <= up { due.push(d.clone()); false } else { true });
            st.allow.extend(due);
        }

        if t % 20 == 1 { cfg_guard(); guard(); enforce_dns(); }          // tier cepat
        if t % 60 == 2 { fw(true); policies(true); }                      // tier lambat (proses eksternal lebih banyak)
        if t % 30 == 0 { save_state(); }
        if t % 86_400 == 3 {                                              // harian: heartbeat + perbarui daftar
            notify("Heartbeat harian: Penjaga masih aktif");
            thread::spawn(|| { let _ = update_list(); });
        }
    }
}

/// Pelepasan penuh. Urutan penting: hentikan PENJAGA lebih dulu (tugas guard) agar tidak
/// memulihkan apa yang sedang kita hapus, baru bongkar penegakan dan hapus file.
fn teardown() {
    DYING.store(true, Ordering::SeqCst);
    thread::sleep(Duration::from_secs(2)); // beri waktu notifikasi terkirim
    #[cfg(windows)]
    {
        sh("schtasks", &["/Delete", "/TN", "PenjagaGuard", "/F"]);
        sh("schtasks", &["/Delete", "/TN", "Penjaga", "/F"]);
        sh("reg", &["delete", RUN_KEY, "/v", "Penjaga", "/f"]);
    }
    #[cfg(not(windows))]
    {
        sh("systemctl", &["disable", "--now", "penjaga-guard.timer"]);
        let _ = fs::remove_file("/etc/systemd/system/penjaga-guard.timer");
        let _ = fs::remove_file("/etc/systemd/system/penjaga-guard.service");
    }
    fw(false);
    policies(false);
    restore_dns();
    #[cfg(windows)]
    {
        sh("taskkill", &["/F", "/IM", "penjaga.exe", "/FI", &format!("PID ne {}", std::process::id())]); // tutup tray
        let dir = Path::new(BIN).parent().unwrap().display().to_string();
        // Hapus file setelah proses ini keluar (file yang sedang berjalan tidak bisa dihapus). Best-effort.
        let script = format!("ping -n 6 127.0.0.1 >nul & rmdir /s /q \"{dir}\" & rmdir /s /q \"{HOME}\"");
        let _ = cmd("cmd", &["/C", &script]).spawn();
    }
    #[cfg(not(windows))]
    {
        let script = format!("sleep 2; systemctl disable --now penjaga.service; rm -f /etc/systemd/system/penjaga.service; systemctl daemon-reload; rm -rf '{HOME}' '{BIN}' '/usr/local/lib/penjaga'");
        let _ = Command::new("setsid").args(["sh", "-c", &script]).spawn();
    }
    std::process::exit(0);
}

// ======================================================================================
// TRAY (Windows)
// ======================================================================================

#[cfg(windows)]
fn tray() {
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    unsafe { windows_sys::Win32::System::Console::FreeConsole() }; // sembunyikan jendela konsol
    // Ikon dibuat lewat kode (tanpa file gambar): lingkaran hijau berbingkai putih.
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
    let req = MenuItem::new("", false, None);
    let hint = MenuItem::new("Dilindungi. Lepas: penjaga uninstall", false, None);
    let _ = menu.append(&st);
    let _ = menu.append(&cnt);
    let _ = menu.append(&req);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&hint);
    let tray = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("Penjaga - filter internet").with_icon(icon).build().unwrap();

    ev.run(move |_, _, flow| {
        let _ = &tray; // jaga ikon tetap hidup
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_secs(5));
        match ctl("STATUS") {
            Some(r) => {
                let get = |k: &str| r.split_whitespace().find_map(|x| x.strip_prefix(k)).unwrap_or("0").to_string();
                st.set_text("Status: AKTIF");
                cnt.set_text(format!("Terblokir: {}", get("blocked=")));
                req.set_text(if get("req=") == "1" { "Ada permintaan pelepasan berjalan" } else { "Tidak ada permintaan pelepasan" });
            }
            None => st.set_text("Status: MATI! (sedang dipulihkan)"),
        }
    });
}
#[cfg(not(windows))]
fn tray() { println!("Ikon tray hanya untuk Windows (Linux berjalan sebagai layanan systemd)."); }

// ======================================================================================
// CLI
// ======================================================================================

fn ask(q: &str) -> String {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn install() {
    need_root();
    // Mencegah "install ulang untuk mengosongkan password/masa tunggu".
    if Path::new(BIN).exists() || read_cfg().is_some() {
        println!("Sudah terpasang. Gunakan 'penjaga repair' (pulihkan) atau 'penjaga uninstall' (lepas, berpassword).");
        return;
    }
    let pw = rpassword::prompt_password("Buat password pelepasan (idealnya diketik & dipegang pendamping): ").unwrap_or_default();
    if pw.len() < 8 || pw != rpassword::prompt_password("Ulangi password: ").unwrap_or_default() {
        eprintln!("Password tidak cocok atau kurang dari 8 karakter.");
        return;
    }
    let delay: f64 = ask("Masa tunggu pelepasan, jam [24]: ").parse().unwrap_or(24.0f64).max(1.0);
    let confirm: f64 = ask("Jendela konfirmasi setelahnya, jam [6]: ").parse().unwrap_or(6.0f64).max(1.0);
    let webhook = ask("URL webhook pendamping (mis. https://ntfy.sh/topik-rahasia, kosong = tanpa): ");
    if !webhook.is_empty() && !webhook.starts_with("https://") && !webhook.starts_with("http://") {
        eprintln!("Webhook harus diawali http:// atau https://");
        return;
    }

    let _ = fs::create_dir_all(HOME);
    #[cfg(windows)]
    sh("icacls", &[HOME, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(HOME, fs::Permissions::from_mode(0o700));
    }
    let mut fails: Vec<&str> = Vec::new();
    let me = std::env::current_exe().unwrap();
    for b in [BIN, BIN2] {
        let _ = fs::create_dir_all(Path::new(b).parent().unwrap());
        if fs::copy(&me, b).is_err() { fails.push("salin biner"); }
    }
    let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    save_cfg(&Cfg { hash: hashpw(&pw, &salt), salt, delay_h: delay, confirm_h: confirm, webhook });
    match update_list() {
        Ok(n) => println!("{n} domain masuk daftar blokir."),
        Err(e) => println!("Peringatan: {e}. Memakai kata kunci + DNS hulu dulu; daftar akan dicoba lagi otomatis."),
    }
    if !setup_service() { fails.push("pemasangan layanan/tugas"); }
    #[cfg(windows)]
    {
        sh("schtasks", &["/Run", "/TN", "Penjaga"]);
        let _ = Command::new(BIN).arg("tray").spawn();
    }
    #[cfg(not(windows))]
    sh("systemctl", &["start", "penjaga.service"]);
    thread::sleep(Duration::from_secs(3));
    if ctl("STATUS").is_none() { fails.push("mesin tidak merespons"); }
    if fails.is_empty() { println!("Terpasang. Filter aktif dan otomatis jalan tiap boot."); }
    else { println!("SELESAI DENGAN MASALAH: {}", fails.join(", ")); }
}

/// Pulihkan layanan & salinan biner tanpa mengubah konfigurasi apa pun.
fn repair() {
    need_root();
    if let Some(h) = std::env::current_exe().ok().and_then(|m| file_hash(&m)) { *wlock(&MY_HASH) = h; }
    ensure_copies();
    println!("{}", if setup_service() { "Layanan dipulihkan." } else { "Sebagian langkah gagal." });
    guard_once();
}

fn cli_uninstall() {
    let pw = rpassword::prompt_password("Password pelepasan: ").unwrap_or_default();
    let Some(r) = ctl(&format!("UNINSTALL {}", hex(pw.as_bytes()))) else {
        return println!("Mesin Penjaga tidak berjalan. Coba: penjaga repair");
    };
    let w: Vec<&str> = r.split_whitespace().collect();
    let n: f64 = w.get(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    match w.first().copied() {
        Some("REQ") => println!("Permintaan dicatat. Tunggu {:.1} jam, lalu jalankan perintah ini lagi untuk mengonfirmasi (ada batas waktunya).", n / 3600.0),
        Some("WAIT") => println!("Belum waktunya. Sisa {:.1} jam.", n / 3600.0),
        Some("DONE") => println!("Dikonfirmasi. Penjaga sedang dilepas; DNS akan dikembalikan."),
        Some("BADPW") => println!("Password salah."),
        Some("LOCKED") => println!("Terkunci karena terlalu banyak salah. Coba lagi dalam {:.0} menit.", n / 60.0),
        _ => println!("Respons tak dikenal: {r}"),
    }
}

fn cli_allow(dom: Option<&String>) {
    let Some(d) = dom.and_then(|d| clean_domain(d)) else { return println!("Pemakaian: penjaga allow <domain>") };
    let pw = rpassword::prompt_password("Password: ").unwrap_or_default();
    match ctl(&format!("ALLOW {} {}", hex(pw.as_bytes()), d)).as_deref() {
        Some(r) if r.starts_with("OK") => println!("{d} akan dibuka setelah masa tunggu."),
        Some(r) => println!("Ditolak: {r}"),
        None => println!("Mesin tidak berjalan."),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("run") => run(),
        Some("tray") => tray(),
        Some("guard-once") => guard_once(),
        Some("install") => install(),
        Some("repair") => repair(),
        Some("uninstall") => cli_uninstall(),
        Some("allow") => cli_allow(a.get(2)),
        Some("status") => println!("{}", ctl("STATUS").unwrap_or_else(|| "Mesin TIDAK berjalan".into())),
        Some("cancel") => println!("{}", ctl("CANCEL").unwrap_or_else(|| "Mesin tidak berjalan".into())),
        Some("update-list") => println!("{}", ctl("UPDATE").unwrap_or_else(|| "Mesin tidak berjalan".into())),
        Some("block") => match a.get(2) {
            Some(d) => println!("{}", ctl(&format!("BLOCK {d}")).unwrap_or_else(|| "Mesin tidak berjalan".into())),
            None => println!("Pemakaian: penjaga block <domain>"),
        },
        _ => println!("Penjaga v2\n  install | repair | status | uninstall | cancel | allow <domain> | block <domain> | update-list"),
    }
}

// ======================================================================================
// UJI UNIT (cargo test)
// ======================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let q = build_query([1, 2], "WWW.Example.com", 1);
        let (n, t, e) = parse(&q).unwrap();
        assert_eq!((n.as_str(), t, e), ("www.example.com", 1, q.len()));
    }
    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(&[0u8; 5]).is_none());
        let mut q = build_query([1, 2], "a.com", 1);
        q[12] = 0xC0; // pointer di bagian pertanyaan = tidak sah
        assert!(parse(&q).is_none());
    }
    #[test]
    fn reply_and_answers_roundtrip() {
        let q = build_query([9, 9], "a.com", 1);
        let (_, _, end) = parse(&q).unwrap();
        let r = reply(&q, end, 0, &[(1, vec![1, 2, 3, 4])]);
        assert_eq!(answers_of(&r, 1).unwrap(), vec![(1, vec![1, 2, 3, 4])]);
        assert_eq!(&r[..2], &[9, 9]);
    }
    #[test]
    fn blocking_rules() {
        *wlock(&BLOCK) = Some(["bad.com".to_string()].into_iter().collect());
        assert!(is_blocked("x.bad.com"));
        assert!(!is_blocked("good.com"));
        assert!(is_blocked("xxx-site.org"));   // kata kunci
        assert!(is_blocked("dns.google"));     // pemutus filter
        assert!(!is_blocked("sussex.ac.uk"));  // tidak salah blok
    }
    #[test]
    fn canary_and_safesearch() {
        assert!(CANARY.contains(&"use-application-dns.net"));
        assert_eq!(safe_target("www.youtube.com"), Some("restrict.youtube.com"));
        assert_eq!(safe_target("example.com"), None);
    }
    #[test]
    fn ip_complement() {
        let ex = [(ip2u("127.0.0.0").unwrap(), ip2u("127.255.255.255").unwrap()), (ip2u("1.1.1.3").unwrap(), ip2u("1.1.1.3").unwrap())];
        let r: Vec<String> = complement(&ex).iter().map(|(a, b)| format!("{}-{}", u2ip(*a), u2ip(*b))).collect();
        assert_eq!(r, vec!["0.0.0.0-1.1.1.2", "1.1.1.4-126.255.255.255", "128.0.0.0-255.255.255.255"]);
    }
    #[test]
    fn hex_and_hash() {
        assert_eq!(unhex(&hex("p@ss w0rd".as_bytes())).unwrap(), "p@ss w0rd");
        assert_eq!(hashpw("a", "s"), hashpw("a", "s"));
        assert_ne!(hashpw("a", "s"), hashpw("b", "s"));
    }
    #[test]
    fn domain_cleaning() {
        assert_eq!(clean_domain(" Example.COM. ").as_deref(), Some("example.com"));
        assert!(clean_domain("bad;rm -rf").is_none());
        assert!(clean_domain("nodot").is_none());
    }
}