"""
core/ledger.py — Komponen Dili
Struktur data Block & MedicalLedger dengan hash berantai SHA-256.

Tanggung jawab modul ini:
  - Mendefinisikan skema data satu entri rekam medis (MedicalBlock).
  - Menghitung hash blok dari kombinasi: data_pasien + timestamp + signature + previous_hash.
  - Merantai blok-blok secara kronologis sehingga perubahan satu blok
    mana pun akan langsung memutus seluruh rantai di bawahnya.
  - Menyediakan fungsi validasi integritas rantai penuh (is_chain_valid).
  - Mengekspor/mengimpor ledger ke/dari JSON agar bisa dikirim via API (Taraka).
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional


# ---------------------------------------------------------------------------
# BLOK REKAM MEDIS
# ---------------------------------------------------------------------------

@dataclass
class MedicalBlock:
    """
    Satu entri rekam medis dalam rantai ledger.

    Atribut yang disimpan:
        index          : Nomor urut blok dalam rantai (0 = genesis).
        timestamp      : Waktu pencatatan rekam medis (ISO 8601 UTC).
        patient_data   : Dict berisi data klinis pasien (nama, diagnosa, dsb.).
        faskes_id      : Identitas fasilitas kesehatan penerbit (mis. "RS_A").
        signature_hex  : Tanda tangan digital dokter dalam format hex string
                         (dihasilkan oleh modul crypto.py milik Hadi).
        previous_hash  : SHA-256 blok sebelumnya — inilah "rantai"-nya.
        block_hash     : SHA-256 blok ini sendiri, dihitung setelah semua
                         atribut di atas diketahui.
    """
    index: int
    timestamp: str
    patient_data: dict
    faskes_id: str
    signature_hex: str
    previous_hash: str
    block_hash: str = field(default="", init=False)

    def compute_hash(self) -> str:
        """
        Menghitung SHA-256 blok ini dari representasi kanonik seluruh
        atributnya (kecuali block_hash itu sendiri, tentu).

        Urutan field di-sort agar output deterministik meski dijalankan
        di Python versi / platform berbeda.
        """
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "patient_data": self.patient_data,
            "faskes_id": self.faskes_id,
            "signature_hex": self.signature_hex,
            "previous_hash": self.previous_hash,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Hitung dan kunci block_hash. Dipanggil sekali saat blok baru dibuat."""
        self.block_hash = self.compute_hash()

    def to_dict(self) -> dict:
        """Konversi ke dict biasa untuk serialisasi JSON."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "MedicalBlock":
        """Rekonstruksi MedicalBlock dari dict (misal: diterima via API Taraka)."""
        block = cls(
            index=data["index"],
            timestamp=data["timestamp"],
            patient_data=data["patient_data"],
            faskes_id=data["faskes_id"],
            signature_hex=data["signature_hex"],
            previous_hash=data["previous_hash"],
        )
        # Pasang kembali hash yang sudah tersimpan (bukan dihitung ulang di sini —
        # validasi dilakukan secara eksplisit via is_chain_valid).
        block.block_hash = data.get("block_hash", "")
        return block


# ---------------------------------------------------------------------------
# LEDGER (RANTAI BLOK)
# ---------------------------------------------------------------------------

class MedicalLedger:
    """
    Rantai rekam medis terdistribusi satu node faskes.

    Aturan rantai:
      - Blok pertama (index=0) adalah *genesis block* dengan previous_hash="0"*64.
      - Setiap blok berikutnya menyimpan block_hash blok sebelumnya sebagai
        previous_hash-nya, membentuk rantai tak terputus.
      - Jika isi satu blok diubah, hash blok tersebut berubah → previous_hash
        blok berikutnya tidak cocok → seluruh rantai setelahnya dinyatakan invalid.
    """

    GENESIS_PREVIOUS_HASH = "0" * 64  # Hash fiktif untuk blok pertama

    def __init__(self, faskes_id: str):
        self.faskes_id = faskes_id
        self.chain: List[MedicalBlock] = []
        self._create_genesis_block()

    # ------------------------------------------------------------------
    # INISIALISASI
    # ------------------------------------------------------------------

    def _create_genesis_block(self) -> None:
        """
        Membuat blok genesis (blok kosong pembuka rantai).
        Genesis block tidak berisi data pasien nyata; ia hanya menjadi
        jangkar kriptografi untuk seluruh rantai berikutnya.
        """
        genesis = MedicalBlock(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            patient_data={"info": "Genesis Block — MedChain-Local"},
            faskes_id=self.faskes_id,
            signature_hex="GENESIS",
            previous_hash=self.GENESIS_PREVIOUS_HASH,
        )
        genesis.seal()
        self.chain.append(genesis)

    # ------------------------------------------------------------------
    # PENAMBAHAN BLOK BARU
    # ------------------------------------------------------------------

    def add_record(
        self,
        patient_data: dict,
        signature_hex: str,
        timestamp: Optional[str] = None,
    ) -> MedicalBlock:
        """
        Menambahkan satu entri rekam medis baru ke rantai.

        Parameter:
            patient_data   : Dict data klinis pasien (dari form dashboard Riki).
            signature_hex  : Tanda tangan digital dokter dalam hex
                             (hasil crypto.py Hadi, sudah dikonversi ke string).
            timestamp      : Opsional. Jika tidak diisi, dipakai waktu sekarang (UTC).

        Return:
            MedicalBlock yang baru ditambahkan (sudah ter-seal).
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        last_block = self.chain[-1]
        new_block = MedicalBlock(
            index=len(self.chain),
            timestamp=timestamp,
            patient_data=patient_data,
            faskes_id=self.faskes_id,
            signature_hex=signature_hex,
            previous_hash=last_block.block_hash,
        )
        new_block.seal()
        self.chain.append(new_block)
        return new_block

    # ------------------------------------------------------------------
    # VALIDASI INTEGRITAS RANTAI
    # ------------------------------------------------------------------

    def is_chain_valid(self) -> tuple[bool, str]:
        """
        Memvalidasi integritas seluruh rantai dari blok ke-1 s/d terakhir.
        (Blok genesis tidak divalidasi karena ia adalah titik kepercayaan awal.)

        Dua pemeriksaan per blok:
          1. Hash tersimpan (block_hash) cocok dengan hash yang dihitung ulang
             dari isi blok saat ini → deteksi manipulasi konten.
          2. previous_hash cocok dengan block_hash blok sebelumnya → deteksi
             penyisipan / penghapusan / pengurutan ulang blok.

        Return:
            (True, "OK")  jika rantai valid.
            (False, pesan_error)  jika ada blok yang rusak/dimanipulasi.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Pemeriksaan 1: integritas konten blok saat ini
            recomputed_hash = current.compute_hash()
            if current.block_hash != recomputed_hash:
                return False, (
                    f"Blok #{current.index} terdeteksi dimanipulasi: "
                    f"hash tersimpan ({current.block_hash[:16]}...) "
                    f"!= hash hitung ulang ({recomputed_hash[:16]}...)."
                )

            # Pemeriksaan 2: kesinambungan rantai (link ke blok sebelumnya)
            if current.previous_hash != previous.block_hash:
                return False, (
                    f"Rantai putus antara blok #{previous.index} dan #{current.index}: "
                    f"previous_hash tidak cocok dengan block_hash blok sebelumnya."
                )

        return True, "Rantai valid. Tidak ada manipulasi terdeteksi."

    # ------------------------------------------------------------------
    # UTILITAS
    # ------------------------------------------------------------------

    @property
    def latest_block(self) -> MedicalBlock:
        """Mengambil blok terbaru (ekor rantai)."""
        return self.chain[-1]

    def get_block_by_index(self, index: int) -> Optional[MedicalBlock]:
        """Mengambil blok berdasarkan nomor urutnya."""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def summary(self) -> dict:
        """Ringkasan status ledger untuk ditampilkan di dashboard (Riki) atau API (Taraka)."""
        valid, message = self.is_chain_valid()
        return {
            "faskes_id": self.faskes_id,
            "total_blok": len(self.chain),
            "hash_terbaru": self.latest_block.block_hash,
            "integritas": "VALID" if valid else "TERKOMPROMI",
            "pesan": message,
        }

    # ------------------------------------------------------------------
    # SERIALISASI (untuk Taraka — sinkronisasi antar-node via API)
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """
        Mengekspor seluruh rantai ke JSON string.
        Dipakai oleh node_api.py (Taraka) saat menyinkronkan data ke peer faskes.
        """
        payload = {
            "faskes_id": self.faskes_id,
            "chain": [block.to_dict() for block in self.chain],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "MedicalLedger":
        """
        Merekonstruksi MedicalLedger dari JSON string yang diterima via API.
        Validasi integritas HARUS dipanggil secara eksplisit setelah ini
        (is_chain_valid()) sebelum data dianggap sah.
        """
        payload = json.loads(json_str)
        ledger = cls.__new__(cls)
        ledger.faskes_id = payload["faskes_id"]
        ledger.chain = [MedicalBlock.from_dict(b) for b in payload["chain"]]
        return ledger


# ---------------------------------------------------------------------------
# DEMO SINGKAT — jalankan: python core/ledger.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from core.crypto import MedicalCrypto, KeyManager, KeySerializer, build_canonical_payload

    print("=" * 65)
    print("DEMO LEDGER — MedChain-Local (Dili)")
    print("=" * 65)

    # 1. Inisialisasi ledger untuk RS_A
    ledger = MedicalLedger(faskes_id="RS_A")
    print(f"\n[1] Ledger RS_A dibuat. Genesis block hash: {ledger.chain[0].block_hash[:20]}...")

    # 2. Siapkan kunci dokter (pakai KeyManager dari Hadi)
    km = KeyManager(storage_dir="keys_demo")
    private_key, public_key = km.load("dokter_A")

    # 3. Tambah rekam medis pertama
    data_pasien_1 = {"nama": "Budi Santoso", "diagnosa": "Demam Berdarah", "dosis": "Paracetamol 500mg"}
    ts1 = "2026-06-20T10:00:00+00:00"
    canonical_1 = build_canonical_payload(data_pasien_1, ts1)
    sig_1 = MedicalCrypto.sign_record(private_key, canonical_1)
    sig_1_hex = KeySerializer.signature_to_hex(sig_1)

    blok_1 = ledger.add_record(data_pasien_1, sig_1_hex, timestamp=ts1)
    print(f"\n[2] Blok #1 ditambahkan.")
    print(f"    Patient : {data_pasien_1['nama']} — {data_pasien_1['diagnosa']}")
    print(f"    Hash    : {blok_1.block_hash[:20]}...")
    print(f"    Prev    : {blok_1.previous_hash[:20]}...")

    # 4. Tambah rekam medis kedua
    data_pasien_2 = {"nama": "Siti Rahayu", "diagnosa": "Tifus", "dosis": "Ciprofloxacin 500mg"}
    ts2 = "2026-06-20T11:30:00+00:00"
    canonical_2 = build_canonical_payload(data_pasien_2, ts2)
    sig_2 = MedicalCrypto.sign_record(private_key, canonical_2)

    blok_2 = ledger.add_record(data_pasien_2, KeySerializer.signature_to_hex(sig_2), timestamp=ts2)
    print(f"\n[3] Blok #2 ditambahkan.")
    print(f"    Patient : {data_pasien_2['nama']} — {data_pasien_2['diagnosa']}")
    print(f"    Hash    : {blok_2.block_hash[:20]}...")

    # 5. Validasi rantai (harus valid)
    valid, msg = ledger.is_chain_valid()
    print(f"\n[4] Validasi awal : {'✅' if valid else '❌'} {msg}")

    # 6. Simulasi manipulasi — ubah langsung field di dalam blok #1
    print("\n[5] Simulasi: penyerang mengubah dosis di blok #1 tanpa menandatangani ulang...")
    ledger.chain[1].patient_data["dosis"] = "Paracetamol 5000mg"  # TANPA seal ulang

    valid_after, msg_after = ledger.is_chain_valid()
    print(f"    Validasi setelah manipulasi: {'✅' if valid_after else '❌'} {msg_after}")

    # 7. Ringkasan
    print(f"\n[6] Ringkasan ledger: {ledger.summary()}")
    print("\n" + "=" * 65)