"""
Cara jalanin (lihat juga run_node_5001.sh / run_node_5002.sh):
    NODE_ID=RS_A NODE_PORT=5001 PEERS=http://localhost:5002 \
        uvicorn network.node_api:app --port 5001

    NODE_ID=RS_B NODE_PORT=5002 PEERS=http://localhost:5001 \
        uvicorn network.node_api:app --port 5002
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.crypto import (
    KeyManager,
    KeySerializer,
    MedicalCrypto,
    build_canonical_payload,
)
from core.ledger import MedicalBlock, MedicalLedger

# ---------------------------------------------------------------------------
# KONFIGURASI NODE (via environment variable, supaya gampang multi-port)
# ---------------------------------------------------------------------------

NODE_ID = os.getenv("NODE_ID", "RS_A")
NODE_PORT = int(os.getenv("NODE_PORT", "5001"))
DOCTOR_ID = os.getenv("DOCTOR_ID", f"dokter_{NODE_ID}")

# Daftar peer dipisah koma, mis: "http://localhost:5002,http://localhost:5003"
_peers_raw = os.getenv("PEERS", "")
PEER_NODES: List[str] = [p.strip() for p in _peers_raw.split(",") if p.strip()]

REQUEST_TIMEOUT = 3  # detik — biar node tidak nge-hang kalau peer mati/belum jalan


# ---------------------------------------------------------------------------
# STATE NODE (in-memory, satu instance per proses/port)
# ---------------------------------------------------------------------------

app = FastAPI(title=f"MedChain Node — {NODE_ID}", version="1.0.0")

ledger = MedicalLedger(faskes_id=NODE_ID)
key_manager = KeyManager(storage_dir=f"keys_{NODE_ID}")
doctor_private_key, doctor_public_key = key_manager.load(DOCTOR_ID)

# Cache kunci publik milik faskes lain, supaya tidak perlu fetch berulang
# tiap kali memverifikasi blok dari peer yang sama.
known_public_keys: Dict[str, object] = {NODE_ID: doctor_public_key}


# ---------------------------------------------------------------------------
# SKEMA REQUEST/RESPONSE
# ---------------------------------------------------------------------------

class TransactionIn(BaseModel):
    """Payload dari dashboard Riki saat dokter input rekam medis baru."""
    nama: str
    diagnosa: str
    obat: Optional[str] = None
    catatan: Optional[str] = None
    extra: Dict[str, str] = Field(default_factory=dict)


class BroadcastIn(BaseModel):
    """Payload blok yang disiarkan satu node ke node lain."""
    sender_faskes_id: str
    sender_public_key_pem: str
    block: dict  # hasil MedicalBlock.to_dict()


# ---------------------------------------------------------------------------
# HELPER INTERNAL
# ---------------------------------------------------------------------------

def _broadcast_to_peers(block: MedicalBlock) -> List[dict]:
    """
    Menyiarkan satu blok yang baru dibuat node ini ke seluruh peer.
    Tidak melempar exception kalau satu peer mati — cukup dicatat statusnya,
    supaya simulasi tetap jalan walau salah satu RS belum online.
    """
    payload = {
        "sender_faskes_id": NODE_ID,
        "sender_public_key_pem": KeySerializer.public_key_to_pem(doctor_public_key),
        "block": block.to_dict(),
    }

    results = []
    for peer_url in PEER_NODES:
        try:
            resp = requests.post(
                f"{peer_url}/broadcast/block", json=payload, timeout=REQUEST_TIMEOUT
            )
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            results.append({"peer": peer_url, "status_code": resp.status_code, "body": body})
        except requests.RequestException as exc:
            results.append({"peer": peer_url, "status_code": None, "error": str(exc)})

    return results


def _try_resync_from_peer(peer_url: str) -> bool:
    """
    Dipanggil kalau node ini terdeteksi ketinggalan (previous_hash blok
    masuk tidak nyambung dengan rantai lokal). Menarik full chain dari
    peer, memvalidasinya, lalu mengadopsinya kalau valid dan lebih panjang
    dari chain lokal (aturan sederhana ala "longest valid chain").
    """
    global ledger
    try:
        resp = requests.get(f"{peer_url}/chain", timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        remote = resp.json()
    except requests.RequestException:
        return False

    remote_ledger = MedicalLedger.from_json(json.dumps(remote))

    valid, _ = remote_ledger.is_chain_valid()
    if valid and len(remote_ledger.chain) > len(ledger.chain):
        # Hanya adopsi rantai bloknya saja — identitas (faskes_id) node ini
        # tetap dipertahankan, supaya label node tidak ikut "ketiban" jadi
        # identitas si peer pengirim.
        ledger.chain = remote_ledger.chain
        return True
    return False


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "node": NODE_ID,
        "port": NODE_PORT,
        "peers": PEER_NODES,
        "message": "MedChain node aktif.",
    }


@app.get("/public_key")
def get_public_key():
    """Endpoint supaya peer lain bisa ambil public key dokter node ini."""
    return {
        "faskes_id": NODE_ID,
        "public_key_pem": KeySerializer.public_key_to_pem(doctor_public_key),
    }


@app.post("/transaction/new")
def new_transaction(tx: TransactionIn):
    """
    Endpoint utama yang dipanggil dashboard (Riki) saat dokter input
    rekam medis baru. Alurnya:
      1. Susun data pasien jadi dict + bentuk payload kanonik.
      2. Tanda tangani pakai kunci privat dokter node ini (Hadi).
      3. Bungkus jadi MedicalBlock & masukkan ke ledger lokal (Dili).
      4. Broadcast blok ke semua peer node lain.
    """
    patient_data = {
        "nama": tx.nama,
        "diagnosa": tx.diagnosa,
        "obat": tx.obat,
        "catatan": tx.catatan,
        **tx.extra,
    }

    timestamp = datetime.now(timezone.utc).isoformat()

    canonical = build_canonical_payload(patient_data, timestamp)
    signature = MedicalCrypto.sign_record(doctor_private_key, canonical)
    signature_hex = KeySerializer.signature_to_hex(signature)

    new_block = ledger.add_record(
        patient_data=patient_data,
        signature_hex=signature_hex,
        timestamp=timestamp,
    )

    broadcast_results = _broadcast_to_peers(new_block)

    return {
        "status": "Rekam medis berhasil dicatat & disiarkan",
        "block": new_block.to_dict(),
        "broadcast": broadcast_results,
    }


@app.post("/broadcast/block")
def receive_block(payload: BroadcastIn):
    """
    Endpoint yang dipanggil node lain saat menyiarkan blok baru.
    Tiga lapis verifikasi sebelum blok diterima ke ledger lokal:
      1. Signature digital valid (data tidak dipalsukan/diubah).
      2. block_hash yang dikirim cocok dengan hasil hitung ulang.
      3. previous_hash nyambung dengan blok terakhir di rantai lokal
         (kalau tidak, coba resync otomatis dari peer dulu).
    """
    sender_id = payload.sender_faskes_id
    try:
        sender_pub_key = KeySerializer.public_key_from_pem(payload.sender_public_key_pem)
        known_public_keys[sender_id] = sender_pub_key
    except Exception:
        raise HTTPException(status_code=400, detail="Public key pengirim tidak valid.")

    incoming_block = MedicalBlock.from_dict(payload.block)

    # --- Verifikasi 1: tanda tangan digital ---
    canonical = build_canonical_payload(incoming_block.patient_data, incoming_block.timestamp)
    signature_bytes = KeySerializer.signature_from_hex(incoming_block.signature_hex)
    sig_valid = MedicalCrypto.verify_signature(sender_pub_key, canonical, signature_bytes)

    if not sig_valid:
        raise HTTPException(
            status_code=403,
            detail="Tanda tangan digital tidak valid — data terindikasi dimanipulasi atau dipalsukan.",
        )

    # --- Verifikasi 2: integritas hash blok itu sendiri ---
    recomputed_hash = incoming_block.compute_hash()
    if recomputed_hash != incoming_block.block_hash:
        raise HTTPException(
            status_code=409,
            detail="Hash blok tidak cocok — isi blok terindikasi diubah saat transit.",
        )

    # --- Verifikasi 3: kesinambungan rantai ---
    if incoming_block.previous_hash != ledger.latest_block.block_hash:
        # Kemungkinan 1: blok ini sudah ada di rantai lokal (sudah pernah
        # diterima sebelumnya, atau baru saja ikut terbawa via full resync
        # di bawah ini). Itu bukan error — cukup anggap sukses (idempotent).
        already_present = any(
            b.block_hash == incoming_block.block_hash for b in ledger.chain
        )
        if already_present:
            valid, msg = ledger.is_chain_valid()
            return {
                "status": "Blok sudah tersinkron sebelumnya (tidak ada perubahan)",
                "chain_valid": valid,
                "message": msg,
                "total_blok": len(ledger.chain),
            }

        # Kemungkinan 2: node ini benar-benar ketinggalan -> coba resync
        # full chain dari peer dulu sebelum menyerah.
        resynced = False
        for p in PEER_NODES:
            if _try_resync_from_peer(p):
                resynced = True
                break

        # Setelah resync, cek lagi: barangkali blok ini sudah ikut terbawa
        # masuk lewat full chain pull tadi.
        already_present_after_resync = any(
            b.block_hash == incoming_block.block_hash for b in ledger.chain
        )
        if already_present_after_resync:
            valid, msg = ledger.is_chain_valid()
            return {
                "status": "Blok berhasil disinkronkan via full chain resync",
                "chain_valid": valid,
                "message": msg,
                "total_blok": len(ledger.chain),
            }

        if not resynced or incoming_block.previous_hash != ledger.latest_block.block_hash:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Rantai lokal tidak sinkron dengan blok masuk (previous_hash tidak cocok) "
                    "dan resync otomatis gagal/belum membuat rantai match."
                ),
            )

    # Lolos semua verifikasi -> terima blok ke ledger lokal
    incoming_block.index = len(ledger.chain)
    ledger.chain.append(incoming_block)

    valid, msg = ledger.is_chain_valid()
    return {
        "status": "Blok berhasil diverifikasi dan disinkronkan",
        "chain_valid": valid,
        "message": msg,
        "total_blok": len(ledger.chain),
    }


@app.get("/chain")
def get_chain():
    """Ekspor seluruh ledger lokal sebagai JSON (dipakai resync antar-node)."""
    return json.loads(ledger.to_json())


@app.get("/status")
def get_status():
    """Ringkasan status integritas ledger node ini — buat dashboard Riki."""
    return ledger.summary()


@app.get("/record/{index}")
def get_record(index: int):
    """Ambil satu blok rekam medis spesifik berdasarkan nomor urutnya."""
    block = ledger.get_block_by_index(index)
    if block is None:
        raise HTTPException(status_code=404, detail="Blok tidak ditemukan.")
    return block.to_dict()
