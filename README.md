# PENJAGA

**PENJAGA** adalah prototipe filter DNS untuk membantu mengurangi akses ke domain yang tidak diinginkan, termasuk domain dewasa dan perjudian. Proyek ini dibuat dengan Rust dan menyediakan perintah untuk instalasi, pemeriksaan status, pembaruan daftar blokir, serta pelepasan dengan kata sandi dan masa tunggu.

> **Status proyek: prototipe eksperimental — belum diaudit dan belum diverifikasi keamanannya.**
>
> Jangan mengandalkan PENJAGA sebagai satu-satunya kontrol keamanan atau parental control. Lakukan pengujian di perangkat milik sendiri atau perangkat yang penggunaannya memang Anda berwenang kelola.

## Fitur yang saat ini terlihat di kode

- DNS lokal melalui UDP pada `127.0.0.1:53`.
- Meneruskan kueri yang tidak diblokir ke upstream DNS yang dikonfigurasi.
- Daftar blokir domain yang diunduh dari sumber StevenBlack.
- Pemblokiran tambahan berdasarkan kata kunci domain.
- Pencatatan kueri yang diblokir ke `blocked.log`.
- Perintah `install`, `status`, `update-list`, `uninstall`, `cancel`, `tray`, dan `run`.
- Integrasi Windows Task Scheduler dan ikon system tray pada Windows.
- Integrasi layanan `systemd` pada Linux.
- Kata sandi pelepasan disimpan sebagai hash PBKDF2-HMAC-SHA256 dengan salt.

Daftar fitur ini menggambarkan implementasi yang tampak pada kode sumber, bukan jaminan bahwa setiap fitur berhasil di semua sistem.

## Platform

Kode memiliki jalur khusus untuk Windows dan Linux. Namun, dukungan platform belum dianggap stabil sebelum diuji pada versi OS dan konfigurasi jaringan yang ditargetkan.

## Persyaratan

- Rust toolchain (`rustc` dan `cargo`).
- Hak Administrator pada Windows atau root pada Linux untuk perintah yang mengubah DNS, firewall, atau layanan.
- Koneksi internet untuk mengunduh daftar blokir.
- Port UDP `53` lokal yang tersedia.

## Build

Pastikan `Cargo.toml` dan `src/main.rs` berada pada struktur standar Cargo:

```text
PENJAGA/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs
```

Kompilasi mode rilis:

```bash
cargo build --release
```

Di Windows, binary biasanya dihasilkan pada:

```text
target\release\<nama-paket>.exe
```

Nama executable mengikuti konfigurasi package/target di `Cargo.toml`. Perintah build belum membuktikan bahwa aplikasi aman atau berfungsi benar pada perangkat target.

## Perintah

Jalankan terminal dengan hak yang sesuai untuk operasi sistem.

```text
penjaga install
penjaga status
penjaga update-list
penjaga cancel
penjaga uninstall
penjaga tray
penjaga run
```

Jika menjalankan dari folder build di Windows, gunakan nama executable yang benar, misalnya:

```powershell
.\target\release\penjaga.exe status
```

Sesuaikan nama file dengan nilai `name` di `Cargo.toml`.

| Perintah | Tujuan yang dimaksud |
|---|---|
| `install` | Membuat konfigurasi kata sandi dan masa tunggu, menyalin binary, memperbarui daftar blokir, lalu menyiapkan layanan/tugas. |
| `status` | Menampilkan hasil pemeriksaan DNS lokal, jumlah entri log, dan status permintaan pelepasan jika tersedia. |
| `update-list` | Mengunduh dan menyimpan daftar domain blokir. |
| `cancel` | Membatalkan permintaan pelepasan yang sedang menunggu. |
| `uninstall` | Memulai atau menyelesaikan alur pelepasan yang menggunakan kata sandi dan masa tunggu. |
| `tray` | Menampilkan ikon system tray pada Windows. |
| `run` | Menjalankan loop DNS dan pemeriksaan penjaga. |

**Penting:** tinjau kode sebelum menjalankan `install` atau `uninstall`. Implementasi saat ini mengubah pengaturan DNS, aturan firewall, tugas terjadwal/layanan, dan lokasi file sistem. Siapkan cara pemulihan jaringan terlebih dahulu.

## Konfigurasi dan data

Lokasi yang didefinisikan kode:

- Windows: `C:\ProgramData\Penjaga`
- Linux: `/opt/penjaga`

Di antaranya, kode menggunakan:

- `config.json` — hash kata sandi, salt, masa tunggu, dan waktu pelepasan.
- `blocklist.txt` — daftar domain yang diblokir.
- `blocked.log` — log permintaan yang diblokir.
- `resolv.bak` — cadangan konfigurasi resolver pada jalur Linux.

Jangan mengunggah `config.json` atau log yang dapat memuat informasi aktivitas pribadi ke repositori publik. Kebijakan retensi, izin akses, dan rotasi log perlu diperkuat.

## Batasan dan risiko yang diketahui

PENJAGA **belum** merupakan mekanisme anti-bypass yang kuat. Berdasarkan peninjauan kode, beberapa risiko yang harus diperbaiki dan diuji meliputi:

1. **Alur instalasi dan pelepasan:** instalasi ulang, validasi kegagalan perintah sistem, dan autentikasi untuk operasi sensitif perlu diperkuat.
2. **File `stop`:** proses saat ini berhenti jika file `stop` ditemukan. File ini bukan bukti autentikasi dan merupakan jalur penghentian yang tidak aman.
3. **Manipulasi waktu:** masa tunggu memakai jam sistem, sehingga perubahan jam dapat memengaruhi penundaan.
4. **DNS dan DoH/DoT:** implementasi Windows yang terlihat hanya menambahkan aturan firewall untuk TCP port 853. Ini tidak menutup semua jalur DNS terenkripsi atau kueri DNS langsung, termasuk kemungkinan jalur IPv6.
5. **Firefox canary dan kebijakan browser:** domain `use-application-dns.net` masuk daftar blokir, tetapi respons DNS yang dibuat kode bukan respons NXDOMAIN yang dibutuhkan untuk perilaku canary Firefox. Kebijakan browser juga belum ditegakkan.
6. **Penjaga-diri:** pemeriksaan layanan/tugas belum memverifikasi seluruh konfigurasi dan tidak menjamin perlindungan jika proses atau mekanisme persistensi dihentikan.
7. **Penanganan paket:** paket DNS yang gagal diparse dapat diteruskan ke upstream; kebijakan fail-closed belum diterapkan.
8. **Keandalan DNS:** implementasi yang tampak hanya menangani UDP, belum menyediakan DNS-over-TCP, dan tidak memiliki cache DNS. Satu thread dibuat untuk setiap paket tanpa batas yang terlihat.
9. **Upstream dan jaringan:** upstream menggunakan DNS biasa melalui port 53; jaringan yang memblokir port ini dapat menyebabkan resolusi gagal.
10. **Task Scheduler dan layanan:** konfigurasi task Windows perlu ditinjau untuk perilaku saat boot, penggunaan baterai, batas waktu, dan pemulihan kegagalan.
11. **Daftar blokir:** daftar tidak memiliki mekanisme pembaruan terjadwal yang kuat atau allowlist. Daftar sumber juga dapat menghasilkan false positive.
12. **Log dan privasi:** log belum memiliki rotasi yang terlihat, dan kontrol aksesnya perlu diverifikasi.
13. **Konten web:** filter DNS tidak memeriksa isi halaman, gambar, atau konten di dalam aplikasi.
14. **Hak Administrator/root:** pengguna yang menguasai hak administratif atau dapat melakukan boot dari media lain berpotensi melewati kontrol lokal.

Daftar di atas adalah temuan peninjauan kode, bukan hasil pengujian penetrasi atau bukti bahwa semua skenario sudah direproduksi.

## Roadmap pengembangan

### Prioritas 1 — Tutup jalur bypass kritis
- Mencegah instalasi ulang tanpa autentikasi yang sah.
- Mengganti mekanisme file `stop` dengan protokol penghentian terautentikasi dan izin file yang benar.
- Mengganti perhitungan masa tunggu berbasis jam dinding dengan rancangan yang tahan manipulasi waktu, serta mendeteksi perubahan jam.

### Prioritas 2 — Perkuat penegakan DNS
- Evaluasi aturan firewall untuk DNS langsung, DoT, DoH, IPv6, dan adapter jaringan baru.
- Perbaiki perilaku canary Firefox dan evaluasi policy resmi untuk browser yang didukung.
- Tetapkan perilaku fail-closed yang aman ketika paket DNS tidak valid.

### Prioritas 3 — Tingkatkan keandalan layanan
- Evaluasi Windows Service atau konfigurasi Task Scheduler yang teruji.
- Verifikasi isi dan konfigurasi task, bukan sekadar keberadaannya.
- Tambahkan DNS-over-TCP, cache, batas konkurensi, timeout dan strategi failover yang terukur.
- Hindari ketergantungan pada polling PowerShell jika tersedia mekanisme event/API yang sesuai.

### Prioritas 4 — Kualitas filter dan privasi
- Tambahkan allowlist dengan kebijakan perubahan yang jelas.
- Tambahkan pembaruan daftar blokir terjadwal, validasi sumber, dan penanganan kegagalan.
- Evaluasi SafeSearch dan daftar domain perjudian yang relevan untuk Indonesia.
- Terapkan rotasi log, pembatasan akses, dan dokumentasi retensi data.

### Prioritas 5 — Akuntabilitas dan distribusi
- Pertimbangkan notifikasi kepada pendamping hanya dengan persetujuan pihak terkait dan perlindungan privasi.
- Tambahkan pengujian otomatis, pemeriksaan integritas, proses rilis yang dapat direproduksi, dan code signing bila didistribusikan.
- Dokumentasikan instalasi, pemulihan DNS, rollback, dan penghapusan secara aman.

## Pengujian sebelum digunakan

Sebelum menggunakan pada sistem utama, buat VM atau perangkat uji dan periksa:

- [ ] Build debug dan release berhasil.
- [ ] Instalasi melaporkan kegagalan jika salah satu langkah OS gagal.
- [ ] DNS normal tetap bekerja pada jaringan yang didukung.
- [ ] Domain uji yang diblokir benar-benar diblokir; domain yang diizinkan tetap bisa diakses.
- [ ] Perubahan adapter, VPN, IPv4/IPv6, sleep/resume, dan reboot diuji.
- [ ] Kata sandi salah, masa tunggu, pembatalan, dan pelepasan diuji.
- [ ] Pemulihan DNS dan firewall setelah uninstall berhasil.
- [ ] Penggunaan CPU/memori dan perilaku saat menerima banyak paket diuji.
- [ ] Log dan konfigurasi tidak dapat dibaca atau dimodifikasi oleh pengguna yang tidak berwenang.
- [ ] Semua keterbatasan dan cara pemulihan didokumentasikan.

## Prinsip penggunaan

Gunakan hanya pada perangkat milik sendiri atau perangkat yang penggunaannya memang Anda berwenang kelola. Jangan memasang filter persisten secara diam-diam pada perangkat orang lain. Untuk perlindungan yang lebih kuat, kombinasikan kontrol endpoint dengan akun harian non-admin, kredensial administrator yang dikelola pihak tepercaya, serta kebijakan router atau DNS terkelola.

## Lisensi

Belum ditentukan. Tambahkan berkas `LICENSE` sebelum distribusi publik, dan pastikan lisensi dependensi serta daftar blokir pihak ketiga sesuai dengan cara distribusinya.
