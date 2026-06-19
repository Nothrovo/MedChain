# MedChain-Local 🏥🔗
> **Distributed Medical Record Integrity Network**  
> Purwarupa Sistem Rekam Medis Terdistribusi Berbasis Blockchain Lokal Menggunakan Kriptografi Asimetris & Hashing SHA-256.

---

## 📌 Deskripsi Proyek
MedChain-Local adalah aplikasi purwarupa untuk mengamankan data Rekam Medis Elektronik (RME) melalui arsitektur jaringan terdistribusi (*localhost multi-port*). Proyek ini mensimulasikan mekanisme integritas data mirip *blockchain* tanpa dependensi jaringan eksternal. Setiap entri rekam medis ditandatangani secara digital oleh dokter menggunakan kunci privat RSA (otentikasi) dan dirantai ke data medis sebelumnya menggunakan fungsi hash SHA-256 (integritas). Jika satu karakter data dimanipulasi, rantai enkripsi akan pecah dan sistem akan mendeteksi fraud secara instan.

## 🛠️ Arsitektur Jaringan & Fitur
* **Kriptografi Asimetris (RSA):** Pembuatan key-pair faskes dan penandatanganan digital rekam medis.
* **Cryptographic Ledger (SHA-256):** Mekanisme tautan data berantai (*hash parent-child*) untuk ketelusuran kronologis.
* **Simulasi P2P Lokal:** API terdistribusi menggunakan FastAPI yang berjalan di beberapa port lokal (misal: `:5001` untuk RS A, `:5002` untuk RS B) guna sinkronisasi data otomatis.
* **Dashboard Interaktif:** Interface Streamlit untuk input rekam medis pasien dan visualisasi audit keamanan data.

---

## 📂 Struktur Repositori
```text
rekam_medis_blockchain/
├── core/
│   ├── crypto.py          # Manajemen kunci RSA & Digital Signature [Hadi]
│   └── ledger.py          # Struktur kelas Block & Berantai SHA-256 [Dili]
├── network/
│   └── node_api.py        # Backend FastAPI & Sinkronisasi Node [Taraka]
├── client/
│   └── dashboard.py       # GUI Dashboard Streamlit [Riki]
└── tests/
    └── attack_simulation.py # Skrip audit & simulasi tampering data [Hadi]
