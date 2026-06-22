"""
network/node_api.py — Komponen Taraka (diintegrasikan oleh PM)
Backend FastAPI untuk simulasi jaringan P2P rekam medis terdistribusi.

Endpoint:
  GET  /api/chain        — Ambil seluruh rantai blok
  GET  /api/validate     — Validasi integritas rantai
  GET  /api/summary      — Ringkasan status ledger
  POST /api/records      — Tambah rekam medis baru (sign + chain)
  POST /api/tamper       — Simulasi tampering (untuk demo audit)
  POST /api/reset        — Reset ledger ke data demo awal
  GET  /api/peers        — Lihat daftar peer node
  POST /api/sync         — Sinkronisasi rantai dari peer (longest chain wins)

Jalankan:
  RS_A:  uvicorn network.node_api:create_app --factory --port 5001
  RS_B:  FASKES_ID=RS_B PEERS=http://localhost:5001 uvicorn network.node_api:create_app --factory --port 5002
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crypto import (
    MedicalCrypto,
    KeyManager,
    KeySerializer,
    build_canonical_payload,
)
from core.ledger import MedicalLedger


# ── Pydantic schemas ────────────────────────────────────────────────────────

class RecordIn(BaseModel):
    nama: str
    diagnosa: str
    dokter: str
    no_rm: Optional[str] = None
    dosis: Optional[str] = "-"
    poli: Optional[str] = "Poli Umum"
    catatan: Optional[str] = "-"


class TamperIn(BaseModel):
    block_index: int
    field: str
    new_value: str


# ── App state (per-node) ────────────────────────────────────────────────────

class NodeState:
    def __init__(self, faskes_id: str, peers: list[str]):
        self.faskes_id = faskes_id
        self.peers = peers
        self.key_manager = KeyManager(storage_dir="keys")
        self.private_key, self.public_key = self.key_manager.load(faskes_id)
        self.ledger = MedicalLedger(faskes_id=faskes_id)
        self._seed_demo_data()

    def _seed_demo_data(self):
        demo_records = [
            {
                "nama": "Budi Santoso",
                "no_rm": "RM-2026-001",
                "diagnosa": "Demam Berdarah",
                "dokter": "dr. Arjuna Santoso, Sp.JP",
                "dosis": "Paracetamol 500mg",
                "poli": "Kardiologi",
                "catatan": "-",
            },
            {
                "nama": "Siti Rahayu",
                "no_rm": "RM-2026-002",
                "diagnosa": "Tifus",
                "dokter": "dr. Bima Pradana, Sp.N",
                "dosis": "Ciprofloxacin 500mg",
                "poli": "Poli Umum",
                "catatan": "-",
            },
            {
                "nama": "Ahmad Fauzi",
                "no_rm": "RM-2026-003",
                "diagnosa": "Hipertensi",
                "dokter": "dr. Arjuna Santoso, Sp.JP",
                "dosis": "Amlodipine 5mg",
                "poli": "Kardiologi",
                "catatan": "-",
            },
        ]
        for rec in demo_records:
            self._add_record(rec)

    def _add_record(self, patient_data: dict, timestamp: str | None = None) -> dict:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        canonical = build_canonical_payload(patient_data, ts)
        signature = MedicalCrypto.sign_record(self.private_key, canonical)
        sig_hex = KeySerializer.signature_to_hex(signature)
        block = self.ledger.add_record(patient_data, sig_hex, timestamp=ts)
        return block.to_dict()

    def verify_block_signature(self, block_dict: dict) -> bool:
        ts = block_dict["timestamp"]
        canonical = build_canonical_payload(block_dict["patient_data"], ts)
        sig_bytes = KeySerializer.signature_from_hex(block_dict["signature_hex"])
        return MedicalCrypto.verify_signature(self.public_key, canonical, sig_bytes)

    def reset(self):
        self.ledger = MedicalLedger(faskes_id=self.faskes_id)
        self._seed_demo_data()


# ── Factory ──────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    faskes_id = os.environ.get("FASKES_ID", "RS_A")
    peers_raw = os.environ.get("PEERS", "")
    peers = [p.strip() for p in peers_raw.split(",") if p.strip()]

    state = NodeState(faskes_id=faskes_id, peers=peers)

    app = FastAPI(
        title=f"MedChain Node — {faskes_id}",
        description="API Rekam Medis Terdistribusi Berbasis Blockchain Lokal",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── GET /api/chain ───────────────────────────────────────────────────

    @app.get("/api/chain")
    def get_chain():
        return {
            "faskes_id": state.faskes_id,
            "length": len(state.ledger.chain),
            "chain": [b.to_dict() for b in state.ledger.chain],
        }

    # ── GET /api/validate ────────────────────────────────────────────────

    @app.get("/api/validate")
    def validate_chain():
        valid, message = state.ledger.is_chain_valid()

        sig_results = []
        for block in state.ledger.chain[1:]:
            bd = block.to_dict()
            sig_ok = state.verify_block_signature(bd)
            sig_results.append({
                "index": block.index,
                "nama": block.patient_data.get("nama", "?"),
                "signature_valid": sig_ok,
            })

        return {
            "chain_valid": valid,
            "message": message,
            "signature_verification": sig_results,
        }

    # ── GET /api/summary ─────────────────────────────────────────────────

    @app.get("/api/summary")
    def get_summary():
        summary = state.ledger.summary()
        summary["public_key_pem"] = KeySerializer.public_key_to_pem(state.public_key)
        return summary

    # ── POST /api/records ────────────────────────────────────────────────

    @app.post("/api/records")
    def add_record(record: RecordIn):
        patient_data = {
            "nama": record.nama,
            "no_rm": record.no_rm or f"RM-AUTO-{len(state.ledger.chain):03d}",
            "diagnosa": record.diagnosa,
            "dokter": record.dokter,
            "dosis": record.dosis,
            "poli": record.poli,
            "catatan": record.catatan,
        }
        block_dict = state._add_record(patient_data)
        return {
            "status": "ok",
            "message": f"Rekam medis {record.nama} berhasil ditambahkan sebagai Blok #{block_dict['index']}",
            "block": block_dict,
        }

    # ── POST /api/tamper ─────────────────────────────────────────────────

    @app.post("/api/tamper")
    def tamper_block(body: TamperIn):
        block = state.ledger.get_block_by_index(body.block_index)
        if block is None:
            raise HTTPException(404, f"Blok #{body.block_index} tidak ditemukan")
        if block.index == 0:
            raise HTTPException(400, "Tidak bisa memanipulasi genesis block")
        if body.field not in block.patient_data:
            raise HTTPException(400, f"Field '{body.field}' tidak ada di patient_data")

        old_value = block.patient_data[body.field]
        block.patient_data[body.field] = body.new_value

        valid, message = state.ledger.is_chain_valid()
        return {
            "status": "tampered",
            "block_index": body.block_index,
            "field": body.field,
            "old_value": old_value,
            "new_value": body.new_value,
            "chain_valid": valid,
            "message": message,
        }

    # ── POST /api/reset ──────────────────────────────────────────────────

    @app.post("/api/reset")
    def reset_ledger():
        state.reset()
        return {
            "status": "ok",
            "message": "Ledger berhasil direset ke data demo awal",
            "length": len(state.ledger.chain),
        }

    # ── GET /api/peers ───────────────────────────────────────────────────

    @app.get("/api/peers")
    def get_peers():
        return {
            "faskes_id": state.faskes_id,
            "peers": state.peers,
        }

    # ── POST /api/sync ───────────────────────────────────────────────────

    @app.post("/api/sync")
    def sync_from_peer(peer_chain: dict):
        """
        Menerima rantai dari peer node. Jika rantai peer lebih panjang
        dan valid, ganti rantai lokal (longest chain rule).
        """
        try:
            incoming = peer_chain.get("chain", [])
            if len(incoming) <= len(state.ledger.chain):
                return {
                    "status": "rejected",
                    "message": "Rantai peer tidak lebih panjang dari rantai lokal",
                    "local_length": len(state.ledger.chain),
                    "peer_length": len(incoming),
                }

            temp_ledger = MedicalLedger.from_json(
                __import__("json").dumps({
                    "faskes_id": peer_chain.get("faskes_id", "unknown"),
                    "chain": incoming,
                })
            )
            valid, msg = temp_ledger.is_chain_valid()
            if not valid:
                return {
                    "status": "rejected",
                    "message": f"Rantai peer tidak valid: {msg}",
                }

            state.ledger = temp_ledger
            return {
                "status": "synced",
                "message": "Rantai lokal diganti dengan rantai peer (lebih panjang & valid)",
                "new_length": len(state.ledger.chain),
            }
        except Exception as e:
            raise HTTPException(400, f"Gagal sinkronisasi: {str(e)}")

    return app


# ── Entrypoint langsung ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "5001"))
    faskes_id = os.environ.get("FASKES_ID", "RS_A")
    print(f"Starting MedChain Node [{faskes_id}] on port {port}...")
    uvicorn.run(create_app(), host="0.0.0.0", port=port)
