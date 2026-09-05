"""
Synthetic Android APK Generator with precise Dalvik ULEB128 structures.
"""

import struct
import zlib
import hashlib
import zipfile
from pathlib import Path

def write_uleb128(val: int) -> bytes:
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        res.append(b)
        if val == 0:
            break
    return bytes(res)

def generate_minimal_dex() -> bytes:
    strings = [
        "Lcom/target/app/MainActivity;",
        "Ljava/lang/Object;",
        "MainActivity.java",
        "isPremium",
        "isRooted",
        "showInterstitialAd",
        "getLicenseKey",
        "()Z",
        "()V",
        "()Ljava/lang/String;",
        "Z",
        "V",
        "Ljava/lang/String;",
        "PREMIUM_LICENSE_OK_2026",
        "Hello OmniAPK Modding Engine"
    ]

    string_data_items = []
    for s in strings:
        utf8 = s.encode("utf-8")
        item = write_uleb128(len(utf8)) + utf8 + b"\x00"
        string_data_items.append(item)

    num_strings = len(strings)
    string_ids_off = 0x70
    type_ids_off = string_ids_off + num_strings * 4
    
    types = [
        0, # Lcom/target/app/MainActivity;
        1, # Ljava/lang/Object;
        10, # Z
        11, # V
        12  # Ljava/lang/String;
    ]
    num_types = len(types)
    
    proto_ids_off = type_ids_off + num_types * 4
    protos = [
        (10, 2, 0), # ()Z
        (11, 3, 0), # ()V
        (12, 4, 0)  # ()Ljava/lang/String;
    ]
    num_protos = len(protos)

    method_ids_off = proto_ids_off + num_protos * 12
    methods = [
        (0, 0, 3), # MainActivity->isPremium() -> ()Z
        (0, 0, 4), # MainActivity->isRooted() -> ()Z
        (0, 1, 5), # MainActivity->showInterstitialAd() -> ()V
        (0, 2, 6), # MainActivity->getLicenseKey() -> ()Ljava/lang/String;
    ]
    num_methods = len(methods)

    class_defs_off = method_ids_off + num_methods * 8
    num_classes = 1
    
    data_off = class_defs_off + num_classes * 32
    
    string_offsets = []
    cur_data_off = data_off
    string_data_blob = bytearray()
    for item in string_data_items:
        string_offsets.append(cur_data_off)
        string_data_blob.extend(item)
        cur_data_off += len(item)

    pad = (4 - (cur_data_off % 4)) % 4
    string_data_blob.extend(b"\x00" * pad)
    cur_data_off += pad

    code_items_blob = bytearray()
    
    # Method 0: isPremium -> return false (const/4 v0, 0 ; return v0)
    code_off_0 = cur_data_off
    code_0 = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 2) + bytes([0x12, 0x00, 0x0F, 0x00])
    code_items_blob.extend(code_0)
    cur_data_off += len(code_0)

    # Method 1: isRooted -> return true (const/4 v0, 1 ; return v0)
    code_off_1 = cur_data_off
    code_1 = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 2) + bytes([0x12, 0x10, 0x0F, 0x00])
    code_items_blob.extend(code_1)
    cur_data_off += len(code_1)

    # Method 2: showInterstitialAd -> return-void
    code_off_2 = cur_data_off
    code_2 = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 1) + bytes([0x0E, 0x00])
    code_items_blob.extend(code_2)
    cur_data_off += len(code_2)

    # Method 3: getLicenseKey -> const-string v0, 13 ; return-object v0
    code_off_3 = cur_data_off
    code_3 = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 3) + bytes([0x1A, 0x00, 0x0D, 0x00, 0x11, 0x00])
    code_items_blob.extend(code_3)
    cur_data_off += len(code_3)

    # Class Data Item
    class_data_off = cur_data_off
    class_data_blob = bytearray()
    class_data_blob.extend(write_uleb128(0)) # static_fields
    class_data_blob.extend(write_uleb128(0)) # instance_fields
    class_data_blob.extend(write_uleb128(0)) # direct_methods
    class_data_blob.extend(write_uleb128(4)) # virtual_methods
    
    # Method 0 (idx 0)
    class_data_blob.extend(write_uleb128(0)) # diff
    class_data_blob.extend(write_uleb128(1)) # access_flags ACC_PUBLIC
    class_data_blob.extend(write_uleb128(code_off_0))

    # Method 1 (idx 1 -> diff 1)
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(code_off_1))

    # Method 2 (idx 2 -> diff 1)
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(code_off_2))

    # Method 3 (idx 3 -> diff 1)
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(1))
    class_data_blob.extend(write_uleb128(code_off_3))

    cur_data_off += len(class_data_blob)
    total_size = cur_data_off

    # Build DEX
    dex_buf = bytearray(total_size)
    
    # Header placeholder
    dex_buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<20I", dex_buf, 0x20,
        total_size, 0x70, 0x12345678, 0, 0, 0,
        num_strings, string_ids_off,
        num_types, type_ids_off,
        num_protos, proto_ids_off,
        0, 0, # field_ids
        num_methods, method_ids_off,
        num_classes, class_defs_off,
        total_size - data_off, data_off
    )

    for i, off in enumerate(string_offsets):
        struct.pack_into("<I", dex_buf, string_ids_off + i * 4, off)

    for i, str_idx in enumerate(types):
        struct.pack_into("<I", dex_buf, type_ids_off + i * 4, str_idx)

    for i, p in enumerate(protos):
        struct.pack_into("<III", dex_buf, proto_ids_off + i * 12, p[0], p[1], p[2])

    for i, m in enumerate(methods):
        struct.pack_into("<HHI", dex_buf, method_ids_off + i * 8, m[0], m[1], m[2])

    struct.pack_into("<IIIIIIII", dex_buf, class_defs_off,
        0, 0x0001, 1, 0, 2, 0, class_data_off, 0
    )

    dex_buf[data_off : data_off + len(string_data_blob)] = string_data_blob
    dex_buf[code_off_0 : code_off_0 + len(code_items_blob)] = code_items_blob
    dex_buf[class_data_off : class_data_off + len(class_data_blob)] = class_data_blob

    # Recalculate checksums
    sha1 = hashlib.sha1(dex_buf[32:]).digest()
    dex_buf[12:32] = sha1
    adler = zlib.adler32(dex_buf[12:]) & 0xFFFFFFFF
    dex_buf[8:12] = struct.pack("<I", adler)

    return bytes(dex_buf)

def generate_sample_apk(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.target.sampleapp"
    android:versionCode="100"
    android:versionName="1.0.0">
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="com.google.android.gms.permission.AD_ID" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="com.android.vending.BILLING" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="Target Sample Game"
        android:theme="@style/AppTheme">
        
        <activity
            android:name="com.target.app.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name="com.google.android.gms.ads.AdActivity"
            android:configChanges="keyboard|keyboardHidden|orientation|screenLayout|uiMode|screenSize|smallestScreenSize"
            android:exported="false"
            android:theme="@android:style/Theme.Translucent" />

        <meta-data
            android:name="com.google.android.gms.ads.APPLICATION_ID"
            android:value="ca-app-pub-3940256099942544~3347511713" />
    </application>
</manifest>"""

    dex_data = generate_minimal_dex()

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex_data)
        zf.writestr("assets/game_config.json", b'{"premium_unlocked": false, "vip_level": 0, "coins": 100}')
        zf.writestr("res/values/strings.xml", b'<resources><string name="app_name">Target Sample Game</string></resources>')

    return output_path

if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "sample_target.apk"
    generate_sample_apk(out)
    print(f"Generated test sample APK at: {out}")
