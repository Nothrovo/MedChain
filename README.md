# MedChain-Local 🏥🔗
> **Distributed Medical Record Integrity Network**  
> Purwarupa Sistem Rekam Medis Terdistribusi Berbasis Blockchain Lokal Menggunakan Kriptografi Asimetris & Hashing SHA-256.

---

## 📌 Deskripsi Proyek
MedChain-Local adalah aplikasi purwarupa untuk mengamankan data Rekam Medis Elektronik (RME) melalui arsitektur jaringan terdistribusi (*localhost multi-port*). Proyek ini mensimulasikan mekanisme integritas data mirip *blockchain* tanpa dependensi jaringan eksternal. Setiap entri rekam medis ditandatangani secara digital oleh dokter menggunakan kunci privat RSA (otentikasi) dan dirantai ke data medis sebelumnya menggunakan fungsi hash SHA-256 (integritas). Jika satu karakter data dimanipulasi, rantai enkripsi akan pecah dan sistem akan mendeteksi fraud secara instan.

## 🛠️ Arsitektur Jaringan & Fitur
* **Kriptografi Asimetris (RSA-2048):** Pembuatan key-pair per-faskes, penandatanganan digital rekam medis (PKCS1v15 + SHA-256), dan verifikasi otomatis.
* **Cryptographic Ledger (SHA-256):** Mekanisme tautan data berantai (*hash parent-child*) untuk ketelusuran kronologis. Manipulasi satu blok memutus seluruh rantai di bawahnya.
* **Simulasi P2P Lokal:** API terdistribusi menggunakan FastAPI yang berjalan di beberapa port lokal (misal: `:5001` untuk RS_A, `:5002` untuk RS_B) dengan sinkronisasi rantai otomatis (*longest chain rule*).
* **Dashboard Interaktif:** Interface HTML/JS yang terhubung langsung ke backend API untuk input rekam medis, visualisasi rantai blok, dan simulasi audit keamanan.

---

## 📂 Struktur Repositori
```text
MedChain/
├── core/
│   ├── __init__.py
│   ├── crypto.py               # Manajemen kunci RSA & Digital Signature [Hadi]
│   └── ledger.py               # Struktur kelas Block & Rantai SHA-256 [Dili]
├── network/
│   └── node_api.py             # Backend FastAPI & Sinkronisasi Node [Taraka]
├── client/
│   └── medchain_hospital.html  # Dashboard Web (HTML/JS) [Riki]
├── tests/
│   ├── __init__.py
│   └── attack_simulation.py    # Skrip audit & simulasi tampering [Hadi]
├── requirements.txt            # Dependency Python
├── .gitignore
└── README.md
```

---

## 🚀 Cara Menjalankan

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Jalankan Backend (Node RS_A)
```bash
python network/node_api.py
```
Server akan berjalan di `http://localhost:5001`. Buka di browser untuk melihat dokumentasi API otomatis (Swagger UI) di `http://localhost:5001/docs`.

### 3. (Opsional) Jalankan Node Kedua (RS_B)
```bash
# Windows (CMD)
set FASKES_ID=RS_B& set PORT=5002& set PEERS=http://localhost:5001& python network/node_api.py

# Windows (PowerShell)
$env:FASKES_ID="RS_B"; $env:PORT="5002"; $env:PEERS="http://localhost:5001"; python network/node_api.py

# Linux/Mac
FASKES_ID=RS_B PORT=5002 PEERS=http://localhost:5001 python network/node_api.py
```

### 4. Buka Dashboard
Buka file `client/medchain_hospital.html` langsung di browser. Dashboard akan terhubung otomatis ke backend di `http://localhost:5001`.

Navigasi ke menu **Blockchain Ledger** untuk:
- Melihat status & overview rantai blok
- Menambahkan rekam medis baru (ditandatangani RSA-2048 secara otomatis)
- Memvisualisasikan rantai blok lengkap
- Menjalankan simulasi audit tampering

### 5. Jalankan Simulasi Serangan (CLI)
```bash
python tests/attack_simulation.py
```

---

## 🔌 API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `GET` | `/api/chain` | Ambil seluruh rantai blok |
| `GET` | `/api/validate` | Validasi integritas rantai + verifikasi signature RSA |
| `GET` | `/api/summary` | Ringkasan status ledger |
| `POST` | `/api/records` | Tambah rekam medis baru (auto-sign RSA-2048) |
| `POST` | `/api/tamper` | Simulasi tampering data (untuk demo audit) |
| `POST` | `/api/reset` | Reset ledger ke data demo awal |
| `GET` | `/api/peers` | Lihat daftar peer node |
| `POST` | `/api/sync` | Sinkronisasi rantai dari peer (longest chain rule) |

---

## 🏗️ Alur Integrasi Modul

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Riki)                          │
│           client/medchain_hospital.html                         │
│      fetch() ←→ http://localhost:5001/api/*                     │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP REST API
┌────────────────────────▼────────────────────────────────────────┐
│                    BACKEND API (Taraka)                          │
│                  network/node_api.py                             │
│   FastAPI + CORS — menerima request, memanggil core modules     │
├─────────────────┬───────────────────────────────────────────────┤
│  crypto.py      │  ledger.py                                    │
│  (Hadi)         │  (Dili)                                       │
│  RSA key mgmt   │  MedicalBlock + MedicalLedger                 │
│  sign / verify  │  SHA-256 hash chain + validasi integritas     │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## 👥 Pembagian Tugas Tim
| Nama | Modul | File |
|------|-------|------|
| Hadi | Kriptografi & Simulasi Serangan | `core/crypto.py`, `tests/attack_simulation.py` |
| Dili | Struktur Blok & Rantai Ledger | `core/ledger.py` |
| Taraka | Backend API & Sinkronisasi Node | `network/node_api.py` |
| Riki | Dashboard Web Frontend | `client/medchain_hospital.html` |
| PM | Koordinasi & Integrasi Modul | Integrasi seluruh komponen |
