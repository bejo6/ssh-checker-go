# sshchecker

`sshchecker` adalah tool **audit kredensial SSH** untuk **pentest internal infrastructure**.  
Digunakan untuk mendeteksi **default / weak credentials** pada host internal, appliance, dan environment enterprise.

Tool ini **bukan brute-force liar**, melainkan dirancang untuk:
- internal security assessment
- credential hygiene check
- audit akun default yang seharusnya sudah dinonaktifkan

---

## ⚠️ Disclaimer

> Tool ini **hanya untuk pengujian keamanan yang sah dan berizin**.  
> Penggunaan terhadap sistem yang bukan milik Anda atau tanpa izin tertulis adalah **ilegal**.  
> **Pengembang tidak bertanggung jawab** atas segala bentuk penyalahgunaan tool ini.  
> Segala risiko dan konsekuensi dari penggunaan tool ini sepenuhnya menjadi tanggung jawab pengguna.

---

## ✨ Features

- Live host detection (host:port)
- SSH credential checking
- Worker pool & chunk-based concurrency
- Configurable delay (rate-limit friendly)
- Adaptive execution (auto worker pool untuk target besar)
- Time statistics (live scan, login scan, total runtime)
- Output format: **text** dan **JSON**
- Cross-platform static binary

---

## 🧠 Use Case

- Internal infrastructure pentest
- Default credentials audit
- Appliance / hypervisor SSH exposure
- Credential reuse detection (user/password list)

---

## 📦 Build

### Requirements

- Go **1.21+**
- GNU Make

Untuk menginstall Go, ikuti panduan resmi di:
https://go.dev/doc/install

Atau via [`gvm`](https://github.com/moovweb/gvm):

```bash
gvm install go1.21.0 -B
gvm use go1.21.0
```

---

### Dependencies

Install module crypto:

```bash
go get golang.org/x/crypto/ssh
```

Jika menggunakan **versi latest** dan terjadi error module, jalankan ulang:

```bash
go mod init ssh-checker
go mod tidy
```

Untuk **Go 1.21.0**, gunakan versi module crypto berikut:

```bash
go get golang.org/x/crypto/ssh@v0.24.0
```

---

### Garble (Opsional – Obfuscation)

Install Garble (latest):

```bash
go install mvdan.cc/garble@latest
```

Untuk **Go 1.21.0**, gunakan versi Garble berikut:

```bash
go install mvdan.cc/garble@v0.12.1
```

---

### 🔨 Build local (current OS)

```bash
make
````

Binary akan tersedia di:

```text
build/sshchecker-<os>-<arch>
```

Contoh:

```text
build/sshchecker-linux-amd64
```

---

### 🌍 Build all platforms

```bash
make all
```

Akan menghasilkan binary untuk:

* Linux
* macOS
* FreeBSD
* OpenBSD
  (dengan berbagai arsitektur)

---

### 🧹 Clean build artifacts

```bash
make clean
```

---

## 🔐 Build dengan Garble (Obfuscation)

Jika ingin binary **lebih sulit dianalisis** (misalnya untuk internal red team / distribution terbatas), gunakan `garble`.

### Contoh build Linux amd64 dengan Garble:

```bash
make build-linux-amd64 GOBUILD="garble -literals -tiny build"
```

Catatan:

* `-literals` → obfuscate string literals
* `-tiny` → binary lebih kecil
* `CGO_ENABLED=0` tetap menghasilkan static binary

---

## 🚀 Usage

### Contoh dasar

```bash
./sshchecker \
  -host 192.168.10.1/24 \
  -user-file users.txt \
  -pass-file pass.txt
```

---

### Dengan worker pool

```bash
./sshchecker \
  -host 192.168.10.1/24 \
  -user-file users.txt \
  -pass-file pass.txt \
  --workers 10
```

---

### Dengan delay (rate-limit friendly)

```bash
./sshchecker \
  -host 192.168.10.1/24 \
  -user-file users.txt \
  -pass-file pass.txt \
  --workers 10 \
  --ssh-delay 400
```

---

## ⚙️ Concurrency Model

`sshchecker` mendukung **dua model eksekusi**:

1. **Chunk-based semaphore**

   * Cocok untuk target kecil
   * Lebih ringan

2. **Worker pool**

   * Cocok untuk target besar
   * Lebih scalable

Worker pool akan **aktif otomatis** jika:

* `--workers` diset
* atau jumlah target login besar

---

## 📊 Time Statistics

Contoh output:

```text
[*] Time statistics:
    Live host check : 10.00s
    SSH login check : 6.33s
    Total runtime   : 16.34s
    Avg time/login  : 3.16s
```

Ini membantu:

* tuning worker
* tuning delay
* memahami bottleneck scan

---

## 📄 Output

### Text (`sshchecker_results.txt`)

```text
192.168.10.167:22 | admin | admin123
```

### JSON (`sshchecker_results.json`)

Digunakan untuk:

* reporting
* integrasi tool lain
* pipeline pentest internal

---

## 🛡️ Best Practice (Recommended)

* Gunakan delay saat scan production
* Jangan gunakan worker berlebihan
* Simpan hasil sebagai bukti audit
* Gunakan hanya pada scope yang disetujui

---

## 🚧 Project Status

**Status:** DEV / Internal Use

Digunakan untuk pengujian internal infrastructure.  
Tidak direkomendasikan untuk produksi.

---

## 🧩 Roadmap

* Progress bar + ETA
* Adaptive timeout
* Vendor-specific default credential profiles
* Unified executor (pool + chunk)

---

## 📜 License

Internal use / as defined by organization policy.

```
---

```
