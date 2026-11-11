#!/usr/bin/env python3
"""
Core logic to extract the L3 RSA key (n, d, e) for a given BTLD ID from a
BMW PSdZData security set.

This module is GUI-agnostic. Point it at a folder that contains:
    sec_auth_l3.xml
    sec_security.lic
    sec_keyreference.xml
    bmw_logo.png
    bmw_mini_logo.png

and call extract_l3(input_dir, "btld-000014E0"). Nothing is written to disk
by this module; the caller decides what to do with the result.

PKCS#12 loading uses the `cryptography` library (which bundles its own OpenSSL)
so no external `openssl` binary is required on Windows or macOS. If that path
fails, it falls back to the system `openssl` CLI with the legacy provider.
"""
from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Optional

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from PIL import Image

REQUIRED_FILES = (
    "sec_auth_l3.xml",
    "sec_security.lic",
    "sec_keyreference.xml",
    "bmw_logo.png",
    "bmw_mini_logo.png",
)


class L3Error(Exception):
    """Raised for any expected, user-facing extraction failure."""


@dataclass
class L3Result:
    btld: str
    bl_id: str
    scheme: str
    digest: str
    n: int
    d: int
    e: int
    modlen: int
    n_sha256: str
    passphrase: str = ""
    sha1: str = ""
    aes_key_hex: str = ""

    def as_python(self) -> str:
        return (
            f"L3_N = {hex(self.n)}\n"
            f"L3_D = {hex(self.d)}\n"
            f"L3_E = {self.e}\n"
            f"L3_MODLEN = {self.modlen}\n"
        )


# ---------------------------------------------------------------------------
# 1. Logos -> passphrase XML
# ---------------------------------------------------------------------------
def _extract_hex_from_png(path: str) -> str:
    img = Image.open(path).convert("RGBA")
    w, h = img.size
    px = list(img.getdata())
    by_array = []
    for y in range(h):
        for x in range(w):
            if y * x <= 0:
                continue
            r, g, b, a = px[y * w + x]
            by_array.append(r & 3)
            by_array.append(g & 3)
            by_array.append(b & 3)
    out = []
    n5 = 0
    while n5 + 2 < len(by_array):
        n3 = by_array[n5] | (by_array[n5 + 1] << 2) | (by_array[n5 + 2] << 4)
        n5 += 3
        cc = (n3 & 0xFF) + 32
        if cc == 95:
            break
        out.append(chr(cc))
    hex_str = "".join(c for c in out if c in "0123456789abcdefABCDEF")
    if len(hex_str) % 2:
        hex_str = hex_str[:-1]
    return hex_str


def _passwords_from_logos(logo_png: str, mini_png: str) -> dict:
    logo_hex = _extract_hex_from_png(logo_png)
    mini_hex = _extract_hex_from_png(mini_png)
    data_bytes = bytes.fromhex(logo_hex)
    key_bytes = bytes.fromhex(mini_hex)
    if len(key_bytes) < 16:
        raise L3Error("mini-logo did not yield a 16-byte AES key")
    cipher = AES.new(key_bytes[:16], AES.MODE_CBC, iv=b"\x00" * 16)
    plain = cipher.decrypt(data_bytes[: len(data_bytes) - (len(data_bytes) % 16)])
    pad = plain[-1]
    if 0 < pad < 16:
        plain = plain[:-pad]
    root = ET.fromstring(plain)
    return {n.get("id"): (n.text or "").strip() for n in root.findall(".//passphrase")}


# ---------------------------------------------------------------------------
# 2. sec_security.lic -> PKCS12 -> TLD private key (PEM)
# ---------------------------------------------------------------------------
def _p12_bytes_from_lic(lic_path: str) -> bytes:
    tree = ET.parse(lic_path)
    b64 = "".join((tree.getroot().text or "").split())
    return base64.b64decode(b64)


def _tld_private_key_pem(p12_bytes: bytes, password_upper_hex: str) -> bytes:
    # Preferred: pure-Python via cryptography (bundles OpenSSL, no CLI needed).
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        key, _cert, _extra = pkcs12.load_key_and_certificates(
            p12_bytes, password_upper_hex.encode()
        )
        if key is None:
            raise L3Error("no private key in sec_security.lic with this password")
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except L3Error:
        raise
    except Exception as crypto_err:
        # Fallback: system OpenSSL with the legacy provider.
        pem = _tld_private_key_pem_openssl(p12_bytes, password_upper_hex, crypto_err)
        return pem


def _tld_private_key_pem_openssl(p12_bytes: bytes, password_upper_hex: str, prev_err) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        p12_path = os.path.join(td, "sec_security.p12")
        pem_path = os.path.join(td, "key.pem")
        with open(p12_path, "wb") as f:
            f.write(p12_bytes)
        try:
            r = subprocess.run(
                [
                    "openssl", "pkcs12", "-legacy", "-in", p12_path,
                    "-nocerts", "-nodes", "-passin", "pass:" + password_upper_hex,
                    "-out", pem_path,
                ],
                capture_output=True, text=True,
            )
        except FileNotFoundError:
            raise L3Error(
                "Could not load the PKCS#12 and no 'openssl' binary is available.\n"
                f"Underlying error: {prev_err}"
            )
        if r.returncode != 0 or not os.path.isfile(pem_path) or os.path.getsize(pem_path) == 0:
            raise L3Error("OpenSSL could not unpack the PKCS#12: " + r.stderr.strip())
        txt = open(pem_path).read()
        import re
        m = re.search(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", txt, re.S)
        if not m:
            raise L3Error("no PEM block in OpenSSL output")
        return (m.group(0) + "\n").encode()


# ---------------------------------------------------------------------------
# 3. Session key from sec_keyreference.xml
# ---------------------------------------------------------------------------
def _session_key_from_keyref(keyref_path: str, tld_private_key_pem: bytes) -> bytes:
    tree = ET.parse(keyref_path)
    target = None
    for sk in tree.getroot().findall(".//SessionKey"):
        ref = sk.findtext("Reference") or ""
        if "refKey_AS_L3" in ref:
            target = sk.findtext("keyData")
            break
    if not target:
        raise L3Error("no refKey_AS_L3_* found in sec_keyreference.xml")
    enc = bytes.fromhex(target.strip())
    rsa = RSA.import_key(tld_private_key_pem)
    cipher = PKCS1_v1_5.new(rsa)
    aes = cipher.decrypt(enc, None)
    if aes is None:
        raise L3Error("RSA decryption of the session key failed")
    return aes


# ---------------------------------------------------------------------------
# 4. keyData for the chosen BTLD
# ---------------------------------------------------------------------------
def _find_keydata_for_btld(auth_xml: str, btld_id: str):
    tree = ET.parse(auth_xml)
    want = btld_id.lower().replace("btld-", "").replace("-", "")
    for ak in tree.getroot().iter("AuthenticationKey"):
        bl = (ak.findtext("BL_ID") or "").lower()
        normalized = bl.replace("btld-", "").replace("-", "").split(".")[0]
        if want.startswith(normalized) or normalized.startswith(want):
            kd = ak.findtext("keyData")
            if not kd:
                continue
            elem = ak.find("keyData")
            return bl, elem.get("signatureScheme"), elem.get("digestAlg"), kd.strip()
    raise L3Error(f"no entry for {btld_id} found in sec_auth_l3.xml")


def _decrypt_keydata(keydata_hex: str, aes_key: bytes) -> bytes:
    enc = bytes.fromhex(keydata_hex)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * 16)
    plain = cipher.decrypt(enc)
    pad = plain[-1]
    if 0 < pad < 16:
        plain = plain[:-pad]
    return plain


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def missing_files(input_dir: str) -> list:
    return [f for f in REQUIRED_FILES if not os.path.isfile(os.path.join(input_dir, f))]


def extract_l3(
    input_dir: str,
    btld_id: str,
    log: Optional[Callable[[str], None]] = None,
) -> L3Result:
    """Run the full extraction. `log` is an optional callback for progress text."""
    def _log(msg: str):
        if log:
            log(msg)

    btld_id = btld_id.strip()
    if not btld_id:
        raise L3Error("No BTLD ID given (e.g. btld-000014E0).")
    if not btld_id.lower().startswith("btld-"):
        btld_id = "btld-" + btld_id.lstrip("-")

    miss = missing_files(input_dir)
    if miss:
        raise L3Error(
            "Missing input file(s) in the selected folder:\n  - "
            + "\n  - ".join(miss)
        )

    auth_xml = os.path.join(input_dir, "sec_auth_l3.xml")
    lic = os.path.join(input_dir, "sec_security.lic")
    keyref = os.path.join(input_dir, "sec_keyreference.xml")
    logo = os.path.join(input_dir, "bmw_logo.png")
    mini = os.path.join(input_dir, "bmw_mini_logo.png")

    _log("[1] logos -> passphrases ...")
    pws = _passwords_from_logos(logo, mini)
    if "0" not in pws:
        raise L3Error(f"no <passphrase id='0'> in logo XML (found: {list(pws)})")
    passphrase = pws["0"]
    _log(f"    id=0: {passphrase}")

    _log("[2] SHA1(passphrase) -> PKCS12 password ...")
    sha1_hex = hashlib.sha1(passphrase.encode()).hexdigest().upper()
    _log(f"    sha1: {sha1_hex}")

    _log("[3] sec_security.lic -> PKCS12 -> TLD private key ...")
    p12 = _p12_bytes_from_lic(lic)
    pem = _tld_private_key_pem(p12, sha1_hex)
    _log("    TLD private key loaded.")

    _log("[4] sec_keyreference.xml -> AES session key ...")
    aes = _session_key_from_keyref(keyref, pem)
    _log(f"    AES: {aes.hex()}")

    _log(f"[5] sec_auth_l3.xml -> keyData for {btld_id} ...")
    bl, scheme, digest, kd = _find_keydata_for_btld(auth_xml, btld_id)
    _log(f"    BL_ID: {bl}")
    _log(f"    scheme={scheme}  digest={digest}  len={len(kd) // 2} bytes")

    _log("[6] AES-CBC decrypt of keyData ...")
    der = _decrypt_keydata(kd, aes)
    _log(f"    DER: {len(der)} bytes, first 4: {der[:4].hex()}")

    _log("[7] DER -> RSA private key ...")
    try:
        key = RSA.import_key(der)
    except Exception as e:
        raise L3Error(f"could not parse keyData as an RSA key: {e}")
    modlen = (key.n.bit_length() + 7) // 8
    n_sha = hashlib.sha256(key.n.to_bytes(modlen, "big")).hexdigest()
    _log(f"    n bits: {key.n.bit_length()}   e: {key.e}")
    _log(f"    n_sha256: {n_sha}")
    _log("[8] done.")

    return L3Result(
        btld=btld_id,
        bl_id=bl,
        scheme=scheme or "",
        digest=digest or "",
        n=key.n,
        d=key.d,
        e=key.e,
        modlen=modlen,
        n_sha256=n_sha,
        passphrase=passphrase,
        sha1=sha1_hex,
        aes_key_hex=aes.hex(),
    )
