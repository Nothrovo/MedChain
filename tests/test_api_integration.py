"""
tests/test_api_integration.py — Test end-to-end integrasi API
Menguji seluruh alur: crypto -> ledger -> API -> response

Jalankan: python tests/test_api_integration.py
(Tidak perlu server berjalan — menggunakan TestClient FastAPI)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from network.node_api import create_app

client = TestClient(create_app())


def test_chain_has_demo_data():
    print("=== 1. GET /api/chain — Rantai berisi demo data ===")
    res = client.get("/api/chain")
    assert res.status_code == 200
    data = res.json()
    assert data["faskes_id"] == "RS_A"
    assert data["length"] == 4  # genesis + 3 demo
    assert data["chain"][0]["signature_hex"] == "GENESIS"
    assert data["chain"][1]["patient_data"]["nama"] == "Budi Santoso"
    assert data["chain"][2]["patient_data"]["nama"] == "Siti Rahayu"
    assert data["chain"][3]["patient_data"]["nama"] == "Ahmad Fauzi"
    print("[OK] Rantai berisi genesis + 3 rekam medis demo\n")


def test_chain_valid_on_init():
    print("=== 2. GET /api/validate — Rantai valid saat awal ===")
    res = client.get("/api/validate")
    assert res.status_code == 200
    data = res.json()
    assert data["chain_valid"] is True
    assert "Tidak ada manipulasi" in data["message"] or "valid" in data["message"].lower()
    for sig in data["signature_verification"]:
        assert sig["signature_valid"] is True, f"Blok #{sig['index']} signature invalid!"
    print("[OK] Rantai valid & semua signature RSA terverifikasi\n")


def test_add_record():
    print("=== 3. POST /api/records — Tambah rekam medis baru ===")
    res = client.post("/api/records", json={
        "nama": "Dewi Anggraini",
        "diagnosa": "Pneumonia",
        "dokter": "dr. Hendra Wijaya, Sp.P",
        "dosis": "Amoxicillin 500mg",
        "poli": "Paru",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["block"]["index"] == 4
    assert data["block"]["patient_data"]["nama"] == "Dewi Anggraini"
    assert len(data["block"]["signature_hex"]) > 100  # RSA signature, bukan fake
    assert len(data["block"]["block_hash"]) == 64  # SHA-256 hex

    # Pastikan rantai masih valid setelah penambahan
    val = client.get("/api/validate").json()
    assert val["chain_valid"] is True
    print(f"[OK] Blok #{data['block']['index']} ditambahkan, signature RSA-2048 asli, rantai tetap valid\n")


def test_tamper_detection():
    print("=== 4. POST /api/tamper + GET /api/validate — Deteksi manipulasi ===")
    res = client.post("/api/tamper", json={
        "block_index": 1,
        "field": "dosis",
        "new_value": "Paracetamol 9999mg PALSU",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "tampered"
    assert data["chain_valid"] is False
    assert "dimanipulasi" in data["message"] or "Blok #1" in data["message"]

    val = client.get("/api/validate").json()
    assert val["chain_valid"] is False
    sig_blok1 = next(s for s in val["signature_verification"] if s["index"] == 1)
    assert sig_blok1["signature_valid"] is False
    print("[OK] Manipulasi terdeteksi: hash chain putus & signature invalid\n")


def test_reset():
    print("=== 5. POST /api/reset — Reset ke demo awal ===")
    res = client.post("/api/reset")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["length"] == 4

    val = client.get("/api/validate").json()
    assert val["chain_valid"] is True
    print("[OK] Ledger berhasil direset, rantai valid kembali\n")


def test_summary():
    print("=== 6. GET /api/summary — Ringkasan ledger ===")
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["faskes_id"] == "RS_A"
    assert data["total_blok"] == 4
    assert data["integritas"] == "VALID"
    assert "BEGIN PUBLIC KEY" in data["public_key_pem"]
    print("[OK] Summary lengkap termasuk public key PEM\n")


def test_peers():
    print("=== 7. GET /api/peers — Daftar peer ===")
    res = client.get("/api/peers")
    assert res.status_code == 200
    data = res.json()
    assert data["faskes_id"] == "RS_A"
    assert isinstance(data["peers"], list)
    print("[OK] Peers endpoint berjalan\n")


if __name__ == "__main__":
    print("=" * 65)
    print("TEST INTEGRASI END-TO-END — MedChain API")
    print("crypto.py <-> ledger.py <-> node_api.py")
    print("=" * 65)
    print()

    test_chain_has_demo_data()
    test_chain_valid_on_init()
    test_add_record()
    test_tamper_detection()
    test_reset()
    test_summary()
    test_peers()

    print("=" * 65)
    print("SEMUA TEST LULUS! Integrasi backend berjalan sempurna.")
    print("=" * 65)
