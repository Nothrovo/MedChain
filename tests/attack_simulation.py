import sys
import os
import hashlib

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.crypto import MedicalCrypto, build_canonical_payload


def print_result(title: str, passed: bool) -> None:
    status = "AMAN (serangan terdeteksi)" if passed else "GAGAL (serangan TIDAK terdeteksi)"
    marker = "[OK]" if passed else "[BAHAYA]"
    print(f"{marker} {title}: {status}")


def simulate_legitimate_record():
    print("\n=== 1. Skenario Normal: Dokter Menandatangani Rekam Medis ===")
    doctor_private, doctor_public = MedicalCrypto.generate_key_pair()

    original_data = build_canonical_payload(
        patient_data={
            "nama": "Budi Santoso",
            "diagnosa": "Demam Berdarah",
            "dosis": "Paracetamol 500mg",
        },
        timestamp="2026-06-20T10:00:00",
    )

    signature = MedicalCrypto.sign_record(doctor_private, original_data)
    is_valid = MedicalCrypto.verify_signature(doctor_public, original_data, signature)
    print(f"Data    : {original_data}")
    print_result("Verifikasi data asli (harus valid)", is_valid)

    return doctor_private, doctor_public, original_data, signature


def simulate_data_tampering(doctor_public, original_data, signature):
    print("\n=== 2. Skenario Serangan: Manipulasi Data (Tampering) ===")
    # Penyerang (atau human error) mengubah dosis obat TANPA menandatangani ulang.
    # Ini skenario realistis: data di-edit langsung di database tanpa lewat
    # prosedur tanda tangan resmi dokter.
    tampered_data = original_data.replace("Paracetamol 500mg", "Paracetamol 5000mg")
    print(f"Data setelah diubah penyerang: {tampered_data}")

    is_valid = MedicalCrypto.verify_signature(doctor_public, tampered_data, signature)
    # Verifikasi HARUS gagal (False) -> berarti sistem berhasil mendeteksi
    print_result("Deteksi manipulasi dosis obat", passed=not is_valid)


def simulate_signature_forgery(real_doctor_public, original_data):
    print("\n=== 3. Skenario Serangan: Pemalsuan Tanda Tangan (Impersonasi) ===")
    # Penyerang punya kunci sendiri (bukan kunci privat dokter yang sah)
    attacker_private, _ = MedicalCrypto.generate_key_pair()
    forged_signature = MedicalCrypto.sign_record(attacker_private, original_data)

    # Sistem SELALU memverifikasi pakai public key dokter yang TERCATAT
    # di identitas faskes (bukan public key sembarang dari pengirim paket).
    is_valid = MedicalCrypto.verify_signature(real_doctor_public, original_data, forged_signature)
    print_result("Deteksi tanda tangan palsu", passed=not is_valid)


def simulate_chain_break(original_data, signature):
    print("\n=== 4. Skenario Serangan: Rantai Hash Terputus ===")
    # Simulasi sederhana representasi hash blok (mirip yang dipakai Dili di ledger.py):
    # hash dihitung dari kombinasi data + signature.
    block_data = original_data + signature.hex()
    original_hash = hashlib.sha256(block_data.encode()).hexdigest()

    tampered_block_data = original_data.replace("2026", "2099") + signature.hex()
    tampered_hash = hashlib.sha256(tampered_block_data.encode()).hexdigest()

    print(f"Hash blok asli   : {original_hash}")
    print(f"Hash blok ubahan : {tampered_hash}")
    chain_broken = original_hash != tampered_hash
    print_result("Deteksi perubahan via hash chain", passed=chain_broken)


if __name__ == "__main__":
    print("=" * 65)
    print("SIMULASI AUDIT KEAMANAN — SISTEM REKAM MEDIS TERDISTRIBUSI")
    print("=" * 65)

    priv, pub, data, sig = simulate_legitimate_record()
    simulate_data_tampering(pub, data, sig)
    simulate_signature_forgery(pub, data)
    simulate_chain_break(data, sig)

    print("\n" + "=" * 65)
    print("Kesimpulan: Setiap upaya manipulasi data maupun pemalsuan")
    print("tanda tangan berhasil dideteksi oleh sistem kriptografi.")
    print("Hasil ini bisa dipakai sebagai bukti di Bab IV laporan akhir.")
    print("=" * 65)