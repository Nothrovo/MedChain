import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# 1. OPERASI INTI: generate kunci, tanda tangan, verifikasi
class MedicalCrypto:
    """Operasi kriptografi inti untuk penandatanganan rekam medis."""

    @staticmethod
    def generate_key_pair(key_size: int = 2048):
        """
        Membuat pasangan kunci RSA untuk dokter/faskes.
        public_exponent=65537 adalah nilai standar industri (aman & efisien
        secara komputasi dibanding alternatif lain seperti 3).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_record(private_key: RSAPrivateKey, medical_data: str) -> bytes:
        """
        Menandatangani data rekam medis (string kanonik) dengan kunci privat
        dokter/faskes. Skema PKCS1v15 + SHA-256 dipakai sesuai cetak biru.
        """
        signature = private_key.sign(
            medical_data.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return signature

    @staticmethod
    def verify_signature(public_key: RSAPublicKey, medical_data: str, signature: bytes) -> bool:
        """
        Memverifikasi bahwa `signature` benar dihasilkan dari `medical_data`
        oleh pemilik `public_key`, dan data belum diubah sama sekali sejak
        ditandatangani. Mengembalikan False (bukan exception) untuk semua
        kasus gagal verifikasi agar mudah dipakai di alur validasi blok.
        """
        try:
            public_key.verify(
                signature,
                medical_data.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Menangani signature korup, format salah, dsb.
            return False


# 2. SERIALISASI: kunci & signature perlu dikirim lewat JSON 
class KeySerializer:
    """Konversi kunci & signature ke/dari format yang aman dikirim lewat JSON/API."""

    @staticmethod
    def public_key_to_pem(public_key: RSAPublicKey) -> str:
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    @staticmethod
    def public_key_from_pem(pem_str: str) -> RSAPublicKey:
        return serialization.load_pem_public_key(pem_str.encode("utf-8"))

    @staticmethod
    def private_key_to_pem(private_key: RSAPrivateKey, password: bytes = None) -> str:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        return pem_bytes.decode("utf-8")

    @staticmethod
    def private_key_from_pem(pem_str: str, password: bytes = None) -> RSAPrivateKey:
        return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=password)

    @staticmethod
    def signature_to_hex(signature: bytes) -> str:
        return signature.hex()

    @staticmethod
    def signature_from_hex(signature_hex: str) -> bytes:
        return bytes.fromhex(signature_hex)


# 3. MANAJEMEN KUNCI PER-FASKES: tiap node (RS_A, RS_B, ...) butuh identitas
class KeyManager:
    """
    Mengelola penyimpanan kunci per-faskes di disk lokal, agar tiap node
    (mis. RS_A di port 5001, RS_B di port 5002) punya identitas kriptografi
    yang tidak berubah setiap kali servernya direstart.
    """

    def __init__(self, storage_dir: str = "keys"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def _private_path(self, faskes_id: str) -> str:
        return os.path.join(self.storage_dir, f"{faskes_id}_private.pem")

    def _public_path(self, faskes_id: str) -> str:
        return os.path.join(self.storage_dir, f"{faskes_id}_public.pem")

    def generate_and_save(self, faskes_id: str):
        """Membuat kunci baru untuk sebuah faskes dan menyimpannya ke disk."""
        private_key, public_key = MedicalCrypto.generate_key_pair()

        with open(self._private_path(faskes_id), "w") as f:
            f.write(KeySerializer.private_key_to_pem(private_key))
        with open(self._public_path(faskes_id), "w") as f:
            f.write(KeySerializer.public_key_to_pem(public_key))

        return private_key, public_key

    def load(self, faskes_id: str):
        """Memuat kunci faskes dari disk. Membuat baru otomatis jika belum ada."""
        priv_path, pub_path = self._private_path(faskes_id), self._public_path(faskes_id)

        if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
            return self.generate_and_save(faskes_id)

        with open(priv_path) as f:
            private_key = KeySerializer.private_key_from_pem(f.read())
        with open(pub_path) as f:
            public_key = KeySerializer.public_key_from_pem(f.read())

        return private_key, public_key

# 4. UTIL TAMBAHAN: representasi kanonik data pasien.
def build_canonical_payload(patient_data: dict, timestamp: str) -> str:
    """
    Membentuk representasi string kanonik dari data pasien + timestamp.
    sort_keys=True penting supaya urutan field dict tidak memengaruhi hasil
    sign/hash (kalau tidak, signature bisa "tidak valid" hanya gara-gara
    urutan key JSON beda padahal isinya sama).
    """
    payload = {"patient_data": patient_data, "timestamp": timestamp}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# Demo singkat penggunaan 
if __name__ == "__main__":
    # 1. Faskes (dokter) generate kunci sekali, lalu simpan
    km = KeyManager(storage_dir="keys_demo")
    private_key, public_key = km.load("RS_A")

    # 2. Data rekam medis dibuat kanonik dulu
    data_str = build_canonical_payload(
        patient_data={"nama": "Budi Santoso", "diagnosa": "Demam Berdarah"},
        timestamp="2026-06-20T10:00:00",
    )

    # 3. Tanda tangani
    signature = MedicalCrypto.sign_record(private_key, data_str)
    print("Signature (hex):", KeySerializer.signature_to_hex(signature)[:40], "...")

    # 4. Verifikasi (harus True)
    valid = MedicalCrypto.verify_signature(public_key, data_str, signature)
    print("Verifikasi data asli:", valid)

    # 5. Coba verifikasi dengan data yang sudah diubah (harus False)
    tampered = data_str.replace("Demam Berdarah", "Tifus")
    valid_tampered = MedicalCrypto.verify_signature(public_key, tampered, signature)
    print("Verifikasi data yang dimanipulasi:", valid_tampered)