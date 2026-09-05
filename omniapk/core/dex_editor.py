"""
Pure-Python DEX Bytecode Editor & String Patcher (MT Manager DEX Editor++ Core).
Allows in-place method bytecode patching, opcode substitution, string replacements,
and automatic Adler32 checksum and SHA-1 signature recalculation.
"""

import zlib
import hashlib
import struct
from typing import List, Dict, Any, Optional, Tuple
from omniapk.core.dex_parser import DexParser

class DexEditor:
    """DEX Binary and Bytecode Editor."""
    def __init__(self, dex_data: bytes):
        self.data = bytearray(dex_data)
        self.parser = DexParser(self.data)

    def recalculate_checksums(self) -> None:
        """Recalculate SHA-1 signature (bytes 12..32) and Adler32 checksum (bytes 8..12)."""
        # 1. SHA-1 signature covers offset 32 to end of file
        sha1 = hashlib.sha1(self.data[32:]).digest()
        self.data[12:32] = sha1

        # 2. Adler32 checksum covers offset 12 to end of file
        adler = zlib.adler32(self.data[12:]) & 0xFFFFFFFF
        self.data[8:12] = struct.pack("<I", adler)

    def patch_method_return_true(self, class_name: str, method_name: str) -> bool:
        """
        Patch a method (e.g. isPremium(), isSubscribed(), checkLicense()) to immediately return true (0x1).
        Smali equivalent:
            const/4 v0, 0x1
            return v0
        Bytecode: 0x12 0x10 (const/4 v0, 1), 0x0F 0x00 (return v0)
        """
        method = self._find_method(class_name, method_name)
        if not method or method["code_off"] == 0:
            return False

        code_off = method["code_off"]
        # Ensure registers_size is at least 1
        reg_size = struct.unpack("<H", self.data[code_off : code_off + 2])[0]
        if reg_size < 1:
            self.data[code_off : code_off + 2] = struct.pack("<H", 1)

        insns_size = struct.unpack("<I", self.data[code_off + 12 : code_off + 16])[0]
        if insns_size >= 2:
            # Opcode: const/4 v0, 0x1 (0x12, 0x10) ; return v0 (0x0F, 0x00)
            patch_bytes = bytes([0x12, 0x10, 0x0F, 0x00])
            self.data[code_off + 16 : code_off + 20] = patch_bytes
            self.recalculate_checksums()
            return True
        return False

    def patch_method_return_false(self, class_name: str, method_name: str) -> bool:
        """
        Patch a method (e.g. isRooted(), isEmulator(), isAdEnabled()) to immediately return false (0x0).
        Smali equivalent:
            const/4 v0, 0x0
            return v0
        Bytecode: 0x12 0x00, 0x0F 0x00
        """
        method = self._find_method(class_name, method_name)
        if not method or method["code_off"] == 0:
            return False

        code_off = method["code_off"]
        reg_size = struct.unpack("<H", self.data[code_off : code_off + 2])[0]
        if reg_size < 1:
            self.data[code_off : code_off + 2] = struct.pack("<H", 1)

        insns_size = struct.unpack("<I", self.data[code_off + 12 : code_off + 16])[0]
        if insns_size >= 2:
            patch_bytes = bytes([0x12, 0x00, 0x0F, 0x00])
            self.data[code_off + 16 : code_off + 20] = patch_bytes
            self.recalculate_checksums()
            return True
        return False

    def patch_method_return_void(self, class_name: str, method_name: str) -> bool:
        """
        Patch a method (e.g. loadAd(), showInterstitial(), verifyPurchase()) to immediately return void.
        Smali equivalent:
            return-void
        Bytecode: 0x0E 0x00
        """
        method = self._find_method(class_name, method_name)
        if not method or method["code_off"] == 0:
            return False

        code_off = method["code_off"]
        insns_size = struct.unpack("<I", self.data[code_off + 12 : code_off + 16])[0]
        if insns_size >= 1:
            self.data[code_off + 16 : code_off + 18] = bytes([0x0E, 0x00])
            self.recalculate_checksums()
            return True
        return False

    def patch_bytes(self, offset: int, replacement: bytes) -> bool:
        """Direct raw byte patch at specified offset."""
        if offset + len(replacement) <= len(self.data):
            self.data[offset : offset + len(replacement)] = replacement
            self.recalculate_checksums()
            return True
        return False

    def replace_byte_pattern(self, pattern: bytes, replacement: bytes) -> int:
        """Find and replace all occurrences of a byte pattern across the entire DEX."""
        if len(pattern) != len(replacement):
            raise ValueError("Replacement bytes must have the same length as pattern for raw DEX patching")
        
        count = 0
        idx = 0
        while True:
            idx = self.data.find(pattern, idx)
            if idx == -1:
                break
            self.data[idx : idx + len(replacement)] = replacement
            count += 1
            idx += len(replacement)
            
        if count > 0:
            self.recalculate_checksums()
        return count

    def replace_string_inline(self, old_str: str, new_str: str) -> int:
        """
        In-place string replacement for strings of equal or shorter length.
        Null-padded if shorter.
        """
        old_bytes = old_str.encode("utf-8")
        new_bytes = new_str.encode("utf-8")
        if len(new_bytes) > len(old_bytes):
            raise ValueError("In-place string replacement cannot exceed original string length")

        padded_new = new_bytes + b"\x00" * (len(old_bytes) - len(new_bytes))
        count = self.replace_byte_pattern(old_bytes, padded_new)
        return count

    def _find_method(self, class_name: str, method_name: str) -> Optional[Dict[str, Any]]:
        """Find method by class descriptor and name."""
        for cls in self.parser.classes:
            if cls["name"] == class_name or cls["name"].rstrip(";").endswith(class_name.rstrip(";").lstrip("L")):
                for m in cls["direct_methods"] + cls["virtual_methods"]:
                    if m["name"] == method_name:
                        return m
        return None

    def get_bytes(self) -> bytes:
        """Return finalized modified DEX bytes."""
        self.recalculate_checksums()
        return bytes(self.data)
