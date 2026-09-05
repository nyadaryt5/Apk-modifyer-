# APK Modifyer

One toolkit instead of eight. People normally juggle **Apktool**, **Apktool M**,
**APK Editor / AEE**, **Lucky Patcher**, **JADX**, **Frida** and **MT Manager**
side by side, each with its own interface and its own gaps. This project puts
the useful parts of all of them behind a single CLI and a local web UI — and
adds an AI agent that can drive the whole toolkit for you.

| Engine | Replaces | What it does here |
| --- | --- | --- |
| `apktool` | Apktool | Decompiles to smali + resources and rebuilds, driving the real `apktool` jar |
| `apktool-m` | Apktool M | The same workflow on a connected Android device, over `adb` |
| `aee` | APK Editor / AEE | Edits the manifest, resource strings and files **in place** — pure Python, no JVM, no decompile |
| `patcher` | Lucky Patcher | Reports what a build protects and what it phones home about — **analysis only** |
| `jadx` | JADX / JADX-GUI | Decompiles DEX back to readable Java, driving the real `jadx` binary |
| `frida` | Frida | Dynamic instrumentation: pushes and starts `frida-server`, lists processes, runs your scripts |
| `mtmanager` | MT Manager | APK diffing and split-bundle (XAPK/APKS) handling — **native**, no backend needed |

Three of the engines need nothing but Python, which is the point: you can strip
a permission, rename the app, swap an asset, diff two builds, unpack a split
bundle, re-align and re-sign an APK on a phone under Termux or in a container
with no Android SDK in sight.

Run `apkmod platform` to see what this machine supports, or `apkmod doctor` for
every backend.

## Scope — please read

This is reverse-engineering tooling for apps **you own or are authorised to
inspect**: interoperability, security review, accessibility tweaks, fixing your
own builds, learning how the format works.

The `patcher` engine deliberately does the *diagnostic* half of what Lucky
Patcher does and stops there. What is **not** in this project, by design:

- defeating licence checks or payment gates
- unlocking paid features or generating valid signatures for someone else's app
- altering a live service's entitlements, or cheating in online games
- scanning or editing a running game's memory to change scores or currency

That last one is why **Game Guardian is not part of this toolkit**. Its core
purpose is rewriting a live process's memory to cheat, which the boundary above
excludes; the legitimate ground next to it — finding out *how* an app detects
tampering — is already covered by `apkmod scan` and `apkmod findings`.

Frida is included because instrumentation is ordinary security testing, not
because it can bypass things: no bypass scripts ship with it, and the AI agent
is instructed to refuse requests that cross the line.

It will happily tell you *where* an app checks its own signature. It will not
remove the check.

## Install

```bash
git clone <this repo> && cd Apk-modifyer-
pip install -e .          # gives you the `apkmod` command
```

Python 3.9+, no required dependencies. Optional extras:

```bash
pip install -e '.[apktool]'     # a JVM, for the desktop Apktool engine
pip install -e '.[crosscheck]'  # androguard, to cross-check the binary parsers
pip install -e '.[dev]'         # pytest
apkmod install-apktool          # downloads the apktool jar into ~/.apkmod/cache
```

The AI layer needs no extra install — it talks to providers over HTTPS with the
standard library. The external engines report themselves in `apkmod doctor`
with the exact command to install them:

```bash
apt install jadx              # or download from github.com/skylot/jadx/releases
pip install frida-tools       # frida + frida-ps
```

### Android (Termux) vs Linux desktop

Both are supported and `apkmod platform` tells you which one you are on and
what that enables.

```bash
pkg install python openjdk-17 openssl   # Termux: enables Apktool and the signer
pip install -e .
apkmod platform
```

On Android the device is right there, so prefer on-device editing
(`apkmod adb-launch`) over pushing files to a PC. On a desktop you get a JVM, a
browser for the web UI, and `adb` for reaching a device.

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

Reading the code, and diffing builds:

```bash
apkmod decompile-java app.apk -o java     # JADX: DEX -> readable Java
apkmod java-search java "verifySignature"

apkmod diff old.apk new.apk               # what changed between two builds
apkmod diff old.apk new.apk --json

apkmod bundle-unpack app.xapk -o parts    # split APKs out of a bundle
apkmod bundle-pack parts -o rebuilt.xapk
```

Dynamic instrumentation (device must be rooted):

```bash
apkmod frida-server push --binary frida-server-16.2.1-android-arm64
apkmod frida-server start
apkmod frida-ps
apkmod frida-run --script hook.js --package com.example.app
```

## The AI agent

One command that can drive every tool above. It inspects the APK, decides what
to change, makes the edits, then aligns and signs the result.

```bash
export OPENAI_API_KEY=sk-...      # or ANTHROPIC_API_KEY, GEMINI_API_KEY, ...
apkmod ai-doctor                  # what is configured, and how routing behaves

apkmod ai "what does this app phone home to?" --apk app.apk
apkmod ai "rename it to Test Build and drop the CAMERA permission" \
        --apk app.apk --yes --verbose
```

Mutating tools are gated: without `--yes` the agent reports the change it wants
to make instead of applying it. Every run can write a full transcript:

```bash
apkmod ai "summarise the protections" --apk app.apk --json --transcript run.json
```

### Multiple providers, keys and automatic routing

`~/.apkmod/ai.json` (or `--config`, or `$APKMOD_AI_CONFIG`):

```json
{
  "default_model": "gpt-4o",
  "providers": [
    {
      "name": "openai",
      "keys": ["sk-first", "sk-second"],
      "models": ["gpt-4o", "gpt-4o-mini"]
    },
    {
      "name": "anthropic",
      "keys": ["sk-ant-..."],
      "models": ["claude-sonnet-4-5"]
    },
    {
      "name": "my-gateway",
      "base_url": "https://llm.internal/v1",
      "keys": ["gateway-token"],
      "models": ["llama-3.1-70b"]
    }
  ],
  "routing": {
    "strategy": "priority",
    "max_wait_seconds": 1800,
    "backoff_max_seconds": 60
  }
}
```

Any OpenAI-compatible endpoint works by setting `base_url` — OpenRouter, Groq,
DeepSeek, Mistral, Together, xAI, vLLM, llama.cpp and Ollama all speak that
protocol. Environment keys are merged in too, so a single exported variable
works with no file at all.

Every key of every provider becomes a schedulable endpoint. `strategy` is
`priority` (first healthy one), `round-robin` (spread the load), or
`lowest-latency`.

**Rate limits wait; they do not end the task.** A `429` parks that endpoint for
its `Retry-After` and the request moves to the next key. When every key is
parked, the router sleeps until the soonest frees up and carries on — up to
`max_wait_seconds`, after which it errors rather than hanging forever. A `401`
or `403` disables that key permanently instead of retrying something that will
never work.

```bash
apkmod ai "..." --strategy round-robin --max-wait 3600 --verbose
```

`--verbose` streams the routing decisions, so you can watch it hop providers
and wait out a limit.


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
  axml.py         binary AndroidManifest parse + patch + byte-exact re-serialise
  arsc.py         resources.arsc table + resource-string rewriting
  dex.py          DEX header / string table (MUTF-8) for SDK and integrity greps
  apk.py          container inventory, APK Signing Block (v2/v3) detection
  align.py        native zipalign: pads the local header extra field
  signing.py      native v1 signer/verifier, backend selection, keystore handling
  asn1.py         the slice of DER needed for X.509, RSA and PKCS#7
  analyze.py      static analysis report
  smali.py        search / replace / integrity findings on a decoded tree
  platform_info.py  desktop vs Android detection, and what each enables
  engines/        the seven adapters behind one interface
  ai/             the agent: config, providers, router, client, tools, loop
    config.py       providers and keys from a file, the environment, or both
    providers.py    OpenAI-compatible / Anthropic / Gemini, one normal shape
    router.py       endpoint scheduling; parks and waits on rate limits
    client.py       HTTP plus the retry loop
    tools.py        the 19 capabilities the model may drive
    agent.py        chat -> tool calls -> results -> chat
  server/         dependency-free local web UI
```

The native editor is safe to use because the AXML writer is faithful: parsing
and re-serialising an untouched file returns byte-identical output, and the test
suite asserts exactly that.

Nothing imports `apkmod/ai/` at import time, so if you never configure a key you
never pay for it.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

246 tests. The fixtures in `tests/fixture.py` are hand-encoded from the format
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

The 43 AI tests make no network calls. A scripted transport plays the provider
and the router gets a fake clock and sleeper, so rate-limit behaviour is
asserted exactly — a 429 with `Retry-After: 5` must sleep precisely 5.0 and then
succeed — rather than approximately, and without the suite really sleeping.

What is *not* covered here, because this sandbox has neither the backend nor a
device:

- the `apktool`, `apktool-m`, `jadx` and `frida` engines are exercised only in
  their "backend missing" paths. What *is* tested is the part that is ours:
  that absence is reported honestly, and that the exact argv each one builds is
  the one intended
- apksigner / uber-apk-signer delegation is tested by asserting the exact
  command line that gets built and the graceful failure when they are absent;
  no real v2/v3 signature was produced in this environment
- no test talks to a real AI provider. The wire formats are asserted
  structurally, which means a provider changing its API would not be caught here

## Licence

MIT — see [LICENSE](LICENSE).
