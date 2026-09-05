# APK Modifyer

One toolkit instead of four. People normally juggle **Apktool**, **Apktool M**,
**APK Editor / AEE** and **Lucky Patcher** side by side, each with its own
interface and its own gaps. This project puts the useful parts of all four
behind a single CLI and a local web UI.

| Engine | Replaces | What it does here |
| --- | --- | --- |
| `apktool` | Apktool | Decompiles to smali + resources and rebuilds, driving the real `apktool` jar |
| `apktool-m` | Apktool M | The same workflow on a connected Android device, over `adb` |
| `aee` | APK Editor / AEE | Edits the manifest, resource strings and files **in place** — pure Python, no JVM, no decompile |
| `patcher` | Lucky Patcher | Reports what a build protects and what it phones home about — **analysis only** |

Two of the four need nothing but Python, which is the point: you can strip a
permission, rename the app, swap an asset, re-align and re-sign an APK on a
phone under Termux or in a container with no Android SDK in sight.

## Scope — please read

This is reverse-engineering tooling for apps **you own or are authorised to
inspect**: interoperability, security review, accessibility tweaks, fixing your
own builds, learning how the format works.

The `patcher` engine deliberately does the *diagnostic* half of what Lucky
Patcher does and stops there. What is **not** in this project, by design:

- defeating licence checks or payment gates
- unlocking paid features or generating valid signatures for someone else's app
- altering a live service's entitlements, or cheating in online games

It will happily tell you *where* an app checks its own signature. It will not
remove the check.

## Install

```bash
git clone <this repo> && cd Apk-modifyer-
pip install -e .          # gives you the `apkmod` command
```

Python 3.9+, no required dependencies. Optional extras:

```bash
pip install -e '.[apktool]'    # a JVM, for the desktop Apktool engine
apkmod install-apktool         # downloads the apktool jar into ~/.apkmod/cache
```

Run without installing with `python -m apkmod ...` (or `PYTHONPATH=.`).

## Quick start

```bash
apkmod doctor                       # what is usable on this machine?
apkmod info app.apk                 # package, versions, permissions, signing, biggest files
apkmod analyze app.apk --markdown   # full static report
apkmod scan app.apk                 # anti-tamper + SDK inventory
```

Edit, then sign in one step — `-o` is the final artifact:

```bash
apkmod genkey -o keys --cn "Me"

apkmod remove-permission app.apk -o mod.apk \
    -p android.permission.CAMERA -p android.permission.ACCESS_FINE_LOCATION \
    --sign --key keys/apkmod-key.pem --cert keys/apkmod-cert.pem

apkmod verify mod.apk
```

More edits, all native:

```bash
apkmod manifest app.apk --xml                    # readable manifest
apkmod strings app.apk --match app_name          # resource strings

# rename the app by resource name -- no need to know the current value
apkmod replace-string app.apk -o mod.apk --res-name app_name --new "My App"
apkmod replace-string app.apk -o mod.apk --res-name string/greeting --new "Hi"
apkmod replace-string app.apk -o mod.apk --old "Demo App" --new "My App"   # by exact value
apkmod replace-string app.apk -o mod.apk --index 12 --new "My App"         # by pool index
apkmod set-debuggable app.apk -o mod.apk         # flip android:debuggable
apkmod replace-file app.apk -o mod.apk --entry assets/config.json --file config.json
apkmod replace-file app.apk -o mod.apk --entry assets/extra.txt --file extra.txt --add
apkmod align app.apk -o aligned.apk              # zipalign, .so page-aligned
```

Full smali work goes through Apktool:

```bash
apkmod decode app.apk -o project
apkmod smali-search project "GET_SIGNATURES"
apkmod smali-replace project "oldValue" "newValue"          # dry run
apkmod smali-replace project "oldValue" "newValue" --apply
apkmod findings project                                     # where the integrity checks live
apkmod build project -o rebuilt.apk
apkmod sign rebuilt.apk -o signed.apk --key k.pem --cert c.pem
```

On a phone with Apktool M:

```bash
apkmod adb-push app.apk
apkmod adb-launch
apkmod adb-pull /sdcard/Download/rebuilt.apk -o rebuilt.apk
```

## Web UI

```bash
apkmod serve --host 0.0.0.0 --port 8080
```

Upload an APK, read the reports, apply edits and download the result. No
framework and no CDN, so it works offline; all URLs are relative, so it also
behaves behind a proxy or port forward.

## Signing

`apkmod signers` shows what can sign on this machine:

```
[absent] apksigner            schemes: v1, v2, v3, v4   (Android SDK build-tools)
[absent] uber-apk-signer      schemes: v1, v2, v3       (uber-apk-signer.jar)
[ready ] native (pure Python) schemes: v1               (always available)
```

`--engine auto` (the default) uses apksigner when it is installed, then
uber-apk-signer, then falls back to the native signer. The native path writes a
v1 (JAR) signature itself — `MANIFEST.MF`, `.SF` and a PKCS#7 `.RSA` — with the
RSA and DER done in Python, so it works with no SDK and no JVM.

```bash
apkmod sign app.apk -o signed.apk --keystore release.p12 --storepass secret
apkmod sign app.apk -o signed.apk --key k.pem --cert c.pem --engine native
apkmod verify signed.apk        # v1 validity + which schemes are present
```

Android 11+ also wants a v2/v3 signature. With no build-tools available the
native signer can only produce v1, and it says so rather than implying
otherwise — install build-tools (or drop `uber-apk-signer.jar` in the cache) for
full scheme coverage. `verify` reports exactly which schemes a file carries.

JKS keystores are not read directly; convert once with
`keytool -importkeystore -srckeystore my.jks -destkeystore my.p12 -deststoretype PKCS12`.

## How it works

```
apkmod/
  axml.py      binary AndroidManifest parse + patch + byte-exact re-serialise
  arsc.py      resources.arsc table + resource-string rewriting
  dex.py       DEX header / string table (MUTF-8) for SDK and integrity greps
  apk.py       container inventory, APK Signing Block (v2/v3) detection
  align.py     native zipalign: pads the local header extra field
  signing.py   native v1 signer/verifier, backend selection, keystore handling
  asn1.py      the slice of DER needed for X.509, RSA and PKCS#7
  analyze.py   static analysis report
  smali.py     search / replace / integrity findings on a decoded tree
  engines/     the four adapters behind one interface
  server/      dependency-free local web UI
```

The native editor is safe to use because the AXML writer is faithful: parsing
and re-serialising an untouched file returns byte-identical output, and the test
suite asserts exactly that.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

150 tests. The fixtures in `tests/fixture.py` are hand-encoded from the format
specifications and do **not** import `apkmod`, so the binary parsers are checked
against a second implementation rather than against themselves. The signing
tests also hand the signature to the `openssl` command line for independent
verification, and confirm OpenSSL rejects a tampered one.

`pip install -e '.[crosscheck]'` adds 9 more that compare the AXML, ARSC and DEX
parsers against [androguard](https://github.com/androguard/androguard) — a mature
implementation written by someone else — and have it parse back the output of my
writers. Those tests skip when androguard is absent. Writing them found two real
bugs in the fixtures: the AXML resource map carried invented attribute ids
(`0x0101021b` is `versionCode`, not `package`), and the DEX Adler32 was computed
before the SHA-1 signature was written, so it digested twenty zero bytes and
every real tool rejected the file.

What is *not* covered here, because this sandbox has neither the backend nor a
device:

- the `apktool` and `apktool-m` engines are exercised only in their
  "backend missing" paths — failure messages and command construction are
  tested, a real decode/build round trip is not
- apksigner / uber-apk-signer delegation is tested by asserting the exact
  command line that gets built and the graceful failure when they are absent;
  no real v2/v3 signature was produced in this environment

## Licence

MIT — see [LICENSE](LICENSE).
