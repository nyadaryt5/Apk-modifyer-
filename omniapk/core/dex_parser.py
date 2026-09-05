"""
Pure-Python Dalvik Executable (.dex) Parser and Disassembler.
Parses DEX headers, strings, types, fields, methods, classes, and Dalvik bytecode to Smali.
Works identically on both Linux and Android (Termux) with zero external dependencies.
"""

import struct
from typing import List, Dict, Any, Tuple, Optional

def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Read an unsigned LEB128 integer and return (value, bytes_read)."""
    result = 0
    shift = 0
    read = 0
    while True:
        if offset + read >= len(data):
            break
        b = data[offset + read]
        read += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, read

def read_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a signed LEB128 integer and return (value, bytes_read)."""
    result = 0
    shift = 0
    read = 0
    b = 0
    while True:
        if offset + read >= len(data):
            break
        b = data[offset + read]
        read += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            break
    if (shift < 32) and (b & 0x40) != 0:
        result |= -(1 << shift)
    return result, read

def read_mutf8(data: bytes, offset: int) -> str:
    """Read a MUTF-8 string starting at offset after LEB128 length."""
    strlen, read = read_uleb128(data, offset)
    curr = offset + read
    chars = []
    # Read until null terminator or expected length
    while curr < len(data):
        b = data[curr]
        if b == 0:
            break
        curr += 1
        if b < 0x80:
            chars.append(chr(b))
        elif (b & 0xE0) == 0xC0:
            b2 = data[curr] if curr < len(data) else 0
            curr += 1
            chars.append(chr(((b & 0x1F) << 6) | (b2 & 0x3F)))
        elif (b & 0xF0) == 0xE0:
            b2 = data[curr] if curr < len(data) else 0
            curr += 1
            b3 = data[curr] if curr < len(data) else 0
            curr += 1
            chars.append(chr(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)))
        else:
            chars.append('?')
    return "".join(chars)

# Access Flags Constants
ACC_PUBLIC = 0x1
ACC_PRIVATE = 0x2
ACC_PROTECTED = 0x4
ACC_STATIC = 0x8
ACC_FINAL = 0x10
ACC_SYNCHRONIZED = 0x20
ACC_VOLATILE = 0x40
ACC_TRANSIENT = 0x80
ACC_NATIVE = 0x100
ACC_INTERFACE = 0x200
ACC_ABSTRACT = 0x400
ACC_STRICT = 0x800
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000
ACC_CONSTRUCTOR = 0x10000

# Dalvik Opcode Mapping Table
DALVIK_OPCODES = {
    0x00: ("nop", 1),
    0x01: ("move", 1),
    0x02: ("move/from16", 2),
    0x03: ("move/16", 3),
    0x04: ("move-wide", 1),
    0x05: ("move-wide/from16", 2),
    0x06: ("move-wide/16", 3),
    0x07: ("move-object", 1),
    0x08: ("move-object/from16", 2),
    0x09: ("move-object/16", 3),
    0x0A: ("move-result", 1),
    0x0B: ("move-result-wide", 1),
    0x0C: ("move-result-object", 1),
    0x0D: ("move-exception", 1),
    0x0E: ("return-void", 1),
    0x0F: ("return", 1),
    0x10: ("return-wide", 1),
    0x11: ("return-object", 1),
    0x12: ("const/4", 1),
    0x13: ("const/16", 2),
    0x14: ("const", 3),
    0x15: ("const/high16", 2),
    0x16: ("const-wide/16", 2),
    0x17: ("const-wide/32", 3),
    0x18: ("const-wide", 5),
    0x19: ("const-wide/high16", 2),
    0x1A: ("const-string", 2),
    0x1B: ("const-string/jumbo", 3),
    0x1C: ("const-class", 2),
    0x1D: ("monitor-enter", 1),
    0x1E: ("monitor-exit", 1),
    0x1F: ("check-cast", 2),
    0x20: ("instance-of", 2),
    0x21: ("array-length", 1),
    0x22: ("new-instance", 2),
    0x23: ("new-array", 2),
    0x24: ("filled-new-array", 3),
    0x25: ("filled-new-array/range", 3),
    0x26: ("fill-array-data", 3),
    0x27: ("throw", 1),
    0x28: ("goto", 1),
    0x29: ("goto/16", 2),
    0x2A: ("goto/32", 3),
    0x2B: ("packed-switch", 3),
    0x2C: ("sparse-switch", 3),
    0x38: ("if-eqz", 2),
    0x39: ("if-nez", 2),
    0x3A: ("if-ltz", 2),
    0x3B: ("if-gez", 2),
    0x3C: ("if-gtz", 2),
    0x3D: ("if-lez", 2),
    0x52: ("iget", 2),
    0x53: ("iget-wide", 2),
    0x54: ("iget-object", 2),
    0x55: ("iget-boolean", 2),
    0x56: ("iget-byte", 2),
    0x57: ("iget-char", 2),
    0x58: ("iget-short", 2),
    0x59: ("iput", 2),
    0x5A: ("iput-wide", 2),
    0x5B: ("iput-object", 2),
    0x5C: ("iput-boolean", 2),
    0x5D: ("iput-byte", 2),
    0x5E: ("iput-char", 2),
    0x5F: ("iput-short", 2),
    0x60: ("sget", 2),
    0x61: ("sget-wide", 2),
    0x62: ("sget-object", 2),
    0x63: ("sget-boolean", 2),
    0x64: ("sget-byte", 2),
    0x65: ("sget-char", 2),
    0x66: ("sget-short", 2),
    0x67: ("sput", 2),
    0x68: ("sput-wide", 2),
    0x69: ("sput-object", 2),
    0x6A: ("sput-boolean", 2),
    0x6B: ("sput-byte", 2),
    0x6C: ("sput-char", 2),
    0x6D: ("sput-short", 2),
    0x6E: ("invoke-virtual", 3),
    0x6F: ("invoke-super", 3),
    0x70: ("invoke-direct", 3),
    0x71: ("invoke-static", 3),
    0x72: ("invoke-interface", 3),
    0x74: ("invoke-virtual/range", 3),
    0x75: ("invoke-super/range", 3),
    0x76: ("invoke-direct/range", 3),
    0x77: ("invoke-static/range", 3),
    0x78: ("invoke-interface/range", 3),
}

class DexParser:
    """Complete Pure-Python DEX Binary Parser."""
    def __init__(self, raw_data: bytes):
        self.data = bytearray(raw_data)
        self.header = {}
        self.strings: List[str] = []
        self.types: List[str] = []
        self.protos: List[Dict[str, Any]] = []
        self.fields: List[Dict[str, Any]] = []
        self.methods: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.parse()

    def parse(self):
        if len(self.data) < 0x70:
            raise ValueError("Invalid DEX file: file size smaller than header")
        magic = self.data[0:8]
        if not (magic.startswith(b"dex\n") or magic.startswith(b"cdex")):
            raise ValueError(f"Invalid DEX magic: {magic}")
        
        # Parse Header (104 bytes from offset 8 to 0x70)
        (
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = struct.unpack("<I20s20I", self.data[8:0x70])

        self.header = {
            "magic": magic.decode("latin1", errors="ignore"),
            "checksum": hex(checksum),
            "file_size": file_size,
            "header_size": header_size,
            "string_ids_size": string_ids_size,
            "type_ids_size": type_ids_size,
            "proto_ids_size": proto_ids_size,
            "field_ids_size": field_ids_size,
            "method_ids_size": method_ids_size,
            "class_defs_size": class_defs_size,
        }

        # 1. Parse Strings
        self.strings = []
        for i in range(string_ids_size):
            str_data_off = struct.unpack("<I", self.data[string_ids_off + i * 4 : string_ids_off + i * 4 + 4])[0]
            s = read_mutf8(self.data, str_data_off)
            self.strings.append(s)

        # 2. Parse Type IDs
        self.types = []
        for i in range(type_ids_size):
            descriptor_idx = struct.unpack("<I", self.data[type_ids_off + i * 4 : type_ids_off + i * 4 + 4])[0]
            if descriptor_idx < len(self.strings):
                self.types.append(self.strings[descriptor_idx])
            else:
                self.types.append(f"Type_{descriptor_idx}")

        # 3. Parse Proto IDs
        self.protos = []
        for i in range(proto_ids_size):
            shorty_idx, return_type_idx, parameters_off = struct.unpack("<III", self.data[proto_ids_off + i * 12 : proto_ids_off + i * 12 + 12])
            shorty = self.strings[shorty_idx] if shorty_idx < len(self.strings) else ""
            ret_type = self.types[return_type_idx] if return_type_idx < len(self.types) else ""
            params = []
            if parameters_off != 0 and parameters_off < len(self.data):
                param_size = struct.unpack("<I", self.data[parameters_off : parameters_off + 4])[0]
                for p in range(param_size):
                    type_idx = struct.unpack("<H", self.data[parameters_off + 4 + p * 2 : parameters_off + 6 + p * 2])[0]
                    if type_idx < len(self.types):
                        params.append(self.types[type_idx])
            self.protos.append({"shorty": shorty, "return_type": ret_type, "params": params})

        # 4. Parse Field IDs
        self.fields = []
        for i in range(field_ids_size):
            class_idx, type_idx, name_idx = struct.unpack("<HHI", self.data[field_ids_off + i * 8 : field_ids_off + i * 8 + 8])
            class_name = self.types[class_idx] if class_idx < len(self.types) else ""
            field_type = self.types[type_idx] if type_idx < len(self.types) else ""
            field_name = self.strings[name_idx] if name_idx < len(self.strings) else ""
            self.fields.append({"class": class_name, "type": field_type, "name": field_name})

        # 5. Parse Method IDs
        self.methods = []
        for i in range(method_ids_size):
            class_idx, proto_idx, name_idx = struct.unpack("<HHI", self.data[method_ids_off + i * 8 : method_ids_off + i * 8 + 8])
            class_name = self.types[class_idx] if class_idx < len(self.types) else ""
            proto = self.protos[proto_idx] if proto_idx < len(self.protos) else {}
            method_name = self.strings[name_idx] if name_idx < len(self.strings) else ""
            self.methods.append({"id": i, "class": class_name, "name": method_name, "proto": proto})

        # 6. Parse Class Defs
        self.classes = []
        for i in range(class_defs_size):
            (
                class_idx,
                access_flags,
                superclass_idx,
                interfaces_off,
                source_file_idx,
                annotations_off,
                class_data_off,
                static_values_off,
            ) = struct.unpack("<IIIIIIII", self.data[class_defs_off + i * 32 : class_defs_off + i * 32 + 32])

            class_name = self.types[class_idx] if class_idx < len(self.types) else f"Class_{i}"
            super_name = self.types[superclass_idx] if superclass_idx < len(self.types) and superclass_idx != 0xFFFFFFFF else "Ljava/lang/Object;"
            source_file = self.strings[source_file_idx] if source_file_idx < len(self.strings) and source_file_idx != 0xFFFFFFFF else ""

            class_info = {
                "id": i,
                "name": class_name,
                "access_flags": access_flags,
                "superclass": super_name,
                "source_file": source_file,
                "class_data_off": class_data_off,
                "direct_methods": [],
                "virtual_methods": []
            }

            if class_data_off != 0 and class_data_off < len(self.data):
                self._parse_class_data(class_data_off, class_info)

            self.classes.append(class_info)

    def _parse_class_data(self, offset: int, class_info: dict):
        curr = offset
        static_fields_size, r1 = read_uleb128(self.data, curr); curr += r1
        instance_fields_size, r2 = read_uleb128(self.data, curr); curr += r2
        direct_methods_size, r3 = read_uleb128(self.data, curr); curr += r3
        virtual_methods_size, r4 = read_uleb128(self.data, curr); curr += r4

        # Skip fields
        field_idx = 0
        for _ in range(static_fields_size):
            diff, r = read_uleb128(self.data, curr); curr += r
            _, r = read_uleb128(self.data, curr); curr += r
        for _ in range(instance_fields_size):
            diff, r = read_uleb128(self.data, curr); curr += r
            _, r = read_uleb128(self.data, curr); curr += r

        # Parse direct methods
        method_idx = 0
        for _ in range(direct_methods_size):
            diff, r = read_uleb128(self.data, curr); curr += r
            method_idx += diff
            access_flags, r = read_uleb128(self.data, curr); curr += r
            code_off, r = read_uleb128(self.data, curr); curr += r
            method_meta = self.methods[method_idx] if method_idx < len(self.methods) else {}
            class_info["direct_methods"].append({
                "method_idx": method_idx,
                "name": method_meta.get("name", f"method_{method_idx}"),
                "proto": method_meta.get("proto", {}),
                "access_flags": access_flags,
                "code_off": code_off
            })

        # Parse virtual methods
        method_idx = 0
        for _ in range(virtual_methods_size):
            diff, r = read_uleb128(self.data, curr); curr += r
            method_idx += diff
            access_flags, r = read_uleb128(self.data, curr); curr += r
            code_off, r = read_uleb128(self.data, curr); curr += r
            method_meta = self.methods[method_idx] if method_idx < len(self.methods) else {}
            class_info["virtual_methods"].append({
                "method_idx": method_idx,
                "name": method_meta.get("name", f"method_{method_idx}"),
                "proto": method_meta.get("proto", {}),
                "access_flags": access_flags,
                "code_off": code_off
            })

    def disassemble_method(self, code_off: int) -> Dict[str, Any]:
        """Disassemble a code item into registers, insns, and smali lines."""
        if code_off == 0 or code_off >= len(self.data):
            return {"registers": 0, "instructions": [], "smali": "# Native or abstract method"}

        registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack(
            "<HHHHII", self.data[code_off : code_off + 16]
        )

        insns_data = self.data[code_off + 16 : code_off + 16 + insns_size * 2]
        instructions = []
        smali_lines = [
            f"    .registers {registers_size}",
            f"    # params: {ins_size}, outs: {outs_size}"
        ]

        idx = 0
        while idx < len(insns_data):
            opcode = insns_data[idx]
            info = DALVIK_OPCODES.get(opcode, (f"op_{opcode:02x}", 1))
            op_name, op_words = info[0], info[1]
            op_len = op_words * 2
            
            raw_insn = insns_data[idx : idx + op_len]
            line = f"    {op_name}"
            
            # Format common opcodes for human/smali readability
            if opcode in (0x12,):  # const/4 vx, lit4
                v_dest = (insns_data[idx + 1] & 0x0F)
                lit4 = (insns_data[idx + 1] >> 4)
                line = f"    const/4 v{v_dest}, 0x{lit4:x}"
            elif opcode in (0x0e,): # return-void
                line = "    return-void"
            elif opcode in (0x0f, 0x11): # return vx / return-object vx
                vx = insns_data[idx + 1]
                line = f"    {op_name} v{vx}"
            elif opcode in (0x1a,): # const-string vx, string@BBBB
                if idx + 4 <= len(insns_data):
                    vx = insns_data[idx + 1]
                    str_idx = struct.unpack("<H", insns_data[idx + 2 : idx + 4])[0]
                    str_val = self.strings[str_idx] if str_idx < len(self.strings) else f"str_{str_idx}"
                    # escape string
                    escaped = str_val.replace('"', '\\"').replace('\n', '\\n')
                    line = f'    const-string v{vx}, "{escaped}"'
            elif opcode in (0x6e, 0x70, 0x71, 0x72): # invoke-kind {vC, vD...}, method@BBBB
                if idx + 6 <= len(insns_data):
                    meth_idx = struct.unpack("<H", insns_data[idx + 2 : idx + 4])[0]
                    m_info = self.methods[meth_idx] if meth_idx < len(self.methods) else {}
                    m_cls = m_info.get("class", "?")
                    m_name = m_info.get("name", "?")
                    line = f"    {op_name} -> {m_cls}->{m_name}()"
            elif opcode in (0x60, 0x62, 0x63): # sget
                if idx + 4 <= len(insns_data):
                    vx = insns_data[idx + 1]
                    f_idx = struct.unpack("<H", insns_data[idx + 2 : idx + 4])[0]
                    f_info = self.fields[f_idx] if f_idx < len(self.fields) else {}
                    line = f"    {op_name} v{vx}, {f_info.get('class', '')}->{f_info.get('name', '')}"
            elif opcode in (0x38, 0x39): # if-eqz, if-nez
                if idx + 4 <= len(insns_data):
                    vx = insns_data[idx + 1]
                    offset_target = struct.unpack("<h", insns_data[idx + 2 : idx + 4])[0]
                    line = f"    {op_name} v{vx}, :cond_{idx + offset_target * 2:x}"

            smali_lines.append(line)
            instructions.append({
                "offset": idx,
                "opcode": opcode,
                "name": op_name,
                "hex": raw_insn.hex(),
                "text": line.strip()
            })
            idx += max(2, op_len)

        return {
            "registers": registers_size,
            "ins_size": ins_size,
            "outs_size": outs_size,
            "instructions": instructions,
            "smali": "\n".join(smali_lines)
        }

    def find_strings(self, pattern: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search for string patterns in string pool."""
        results = []
        target = pattern if case_sensitive else pattern.lower()
        for idx, s in enumerate(self.strings):
            match_str = s if case_sensitive else s.lower()
            if target in match_str:
                results.append({"index": idx, "value": s})
        return results

    def find_methods_by_name(self, name_pattern: str) -> List[Dict[str, Any]]:
        """Find methods matching name pattern across all classes."""
        matches = []
        pattern = name_pattern.lower()
        for cls in self.classes:
            for m in cls.get("direct_methods", []) + cls.get("virtual_methods", []):
                if pattern in m["name"].lower():
                    matches.append({
                        "class": cls["name"],
                        "method": m["name"],
                        "access_flags": m["access_flags"],
                        "code_off": m["code_off"],
                        "proto": m.get("proto", {})
                    })
        return matches
