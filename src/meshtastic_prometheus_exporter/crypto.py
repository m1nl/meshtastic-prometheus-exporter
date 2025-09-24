import base64
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAX_BLOCKSIZE = 512


def init_nonce(from_node: int, packet_id: int, extra_nonce: int = 0) -> bytes:
    """
    Builds a 16-byte nonce:
    [0:8]  -> packet_id (little-endian)
    [8:12] -> from_node (little-endian)
    [12:16] -> extra_nonce (little-endian) if used
    """
    nonce = bytearray(16)
    struct.pack_into("<Q", nonce, 0, packet_id)
    struct.pack_into("<I", nonce, 8, from_node)
    if extra_nonce != 0:
        struct.pack_into("<I", nonce, 12, extra_nonce)
    return bytes(nonce)


def encrypt_packet(key: bytes, from_node: int, packet_id: int, payload: bytes, extra_nonce: int = 0) -> bytes:
    if len(payload) > MAX_BLOCKSIZE:
        raise ValueError("Packet too large")

    nonce = init_nonce(from_node, packet_id, extra_nonce)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    return ciphertext


def decrypt_packet(key: bytes, from_node: int, packet_id: int, ciphertext: bytes, extra_nonce: int = 0) -> bytes:
    nonce = init_nonce(from_node, packet_id, extra_nonce)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def xor_hash(data: bytes) -> int:
    h = 0
    for b in data:
        h ^= b
    return h


def generate_channel_hash(channel_name: str, channel_key: dict) -> int:
    if len(channel_key) <= 0:
        return -1  # invalid

    h = xor_hash(channel_name.encode("utf-8"))
    h ^= xor_hash(channel_key)
    return h  # returns int in range 0–255


defaultpsk = bytes([0xD4, 0xF1, 0xBB, 0x3A, 0x20, 0x29, 0x07, 0x59, 0xF0, 0xBC, 0xFF, 0xAB, 0xCF, 0x4E, 0x69, 0x01])


def get_key(psk_bytes: bytes) -> dict:
    key = bytearray(32)

    key_len = len(psk_bytes)
    key[:key_len] = psk_bytes

    if key_len == 1:
        psk_index = key[0]
        key[:32] = defaultpsk
        key_len = 32
        key[-1] = (key[-1] + psk_index - 1) & 0xFF
    elif key_len < 16:
        key_len = 16
    elif key_len < 32 and key_len != 16:
        key_len = 32

    return bytes(key[:key_len])


if __name__ == "__main__":
    from meshtastic.protobuf import mesh_pb2, portnums_pb2

    key = get_key(base64.b64decode("AQ=="))
    print(generate_channel_hash("MediumFast", key))
    decrypted = decrypt_packet(key, 1128208380, 938468410, base64.b64decode("tNVrfDyN"))
    print(decrypted)
    packet = mesh_pb2.Data.FromString(decrypted)
    print(portnums_pb2.PortNum.Name(packet.portnum))
    print(packet.payload)
