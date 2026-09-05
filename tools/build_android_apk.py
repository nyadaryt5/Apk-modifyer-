"""Build a minimal, installable standalone OmniAPK Studio APK.

This uses the project's pure-Python signer and emits Android's binary XML manifest;
plain XML is not accepted inside an APK by Android's package parser.
"""
import struct, zipfile, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omniapk.core.apk_builder import compile_android_activity_dex, generate_app_icon_png
from omniapk.core.apk_signer import ApkSigner


def _utf8(s):
    b = s.encode("utf-8")
    n = len(b)
    return bytes([n]) + bytes([len(b)]) + b + b"\0" if n < 128 else b"\0"


def binary_manifest(package="com.omniapk.studio", version="2.0.0"):
    # Android UTF-8 string pool. Keep all values in the pool, including literals.
    strings = ["android", "http://schemas.android.com/apk/res/android", "manifest",
               "package", package, "versionCode", "versionName", version,
               "application", "label", "OmniAPK Studio", "activity", "name",
               ".MainActivity", "exported"]
    idx = {s:i for i,s in enumerate(strings)}
    data = bytearray()
    offsets=[]
    for s in strings:
        offsets.append(len(data)); b=s.encode(); data += bytes([len(b),len(b)]) + b + b"\0"
    pool_header = struct.pack("<HHIIII", 1, 28, 28+4*len(strings)+len(data), len(strings), 0, 0x100, 28+4*len(strings), 0) if False else None
    # header is type, headerSize, chunkSize, stringCount, styleCount, flags, stringsStart, stylesStart
    pool_size=28+4*len(strings)+len(data)
    data += b"\0" * ((4 - (len(data) % 4)) % 4)
    pool_size=28+4*len(strings)+len(data)
    pool=struct.pack("<HH6I",1,28,pool_size,len(strings),0,0x100,28+4*len(strings),0)
    pool += b"".join(struct.pack("<I",o) for o in offsets) + data
    chunks=bytearray(pool)
    # Resource map lets Android and parsers resolve android:* attribute names.
    ids={"package":0x0101003f,"versionCode":0x0101021b,"versionName":0x0101021c,
         "label":0x01010001,"name":0x01010003,"exported":0x01010010}
    chunks += struct.pack("<HHI",0x0180,8,8+4*len(strings))
    chunks += b"".join(struct.pack("<I",ids.get(s,0)) for s in strings)
    def ns(start=True):
        typ=0x100 if start else 0x101
        return struct.pack("<HHIIIII",typ,16,24,1,0xFFFFFFFF,idx["android"],idx["http://schemas.android.com/apk/res/android"])
    def start(name, attrs):
        # node header + extended element header
        out=struct.pack("<HHIII",0x102,16,16+20+20*len(attrs),1,0xFFFFFFFF)
        out+=struct.pack("<IIHHHHHH",0xFFFFFFFF,idx[name],20,20,len(attrs),0,0,0)
        for an, kind, val in attrs:
            value_idx=idx[val] if kind==3 else 0xFFFFFFFF
            out += struct.pack("<III HBB I", 0xFFFFFFFF if name == "manifest" and an == "package" else idx["http://schemas.android.com/apk/res/android"],idx[an],value_idx,8,kind,0,val if kind!=3 else 0)
        return out
    def end(name):
        return struct.pack("<HHIIIII",0x103,16,24,1,0xFFFFFFFF,0xFFFFFFFF,idx[name])
    chunks += ns(True)
    chunks += start("manifest", [("package",3,package),("versionCode",0x10,200),("versionName",3,version)])
    chunks += start("application", [("label",3,"OmniAPK Studio")])
    chunks += start("activity", [("name",3,".MainActivity"),("exported",0x12,1)])
    chunks += end("activity")
    chunks += end("application")
    chunks += end("manifest")
    chunks += ns(False)
    total=8+len(chunks)
    return struct.pack("<HHI",3,8,total)+chunks


def build(out="OmniAPK_Studio_v2.0.1.apk"):
    root=Path(__file__).resolve().parents[1]; tmp=root/(out+".unsigned")
    dex=compile_android_activity_dex(); icon=generate_app_icon_png()
    with zipfile.ZipFile(tmp,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml",binary_manifest())
        z.writestr("classes.dex",dex)
        z.writestr("res/drawable/ic_launcher.png",icon)
        web=root / "omniapk" / "web"
        for p in web.rglob("*"):
            if p.is_file(): z.write(p, "assets/www/" + p.relative_to(web).as_posix())
        z.writestr("assets/engine_config.json",b'{"engine":"OmniAPK Studio","version":"2.0.1","tools_count":8}')
    ApkSigner.sign_apk(tmp,root/out); tmp.unlink()

if __name__=="__main__": build()
