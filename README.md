# ⚡ OmniAPK Studio & AI Suite

> **The Ultimate 8-in-1 Android & Linux Reverse Engineering, Modding, and Autonomous AI Platform**  
> *Reconstructing Apktool, Apktool M, APK Editor, Lucky Patcher, JADX, Frida, MT Manager, and Game Guardian into a unified engine with Multi-Cloud AI orchestration.*

---

## 🌟 Executive Overview

**OmniAPK Studio** is a unified, cross-platform reverse engineering and modding suite engineered to run natively on both **Linux-based systems** (Ubuntu, Debian, Arch, Fedora, Kali, WSL, Headless Servers) and **Android devices** (Termux, Mobile Web Studio, PWA).

By breaking down and integrating the strengths of the top 8 reverse engineering tools, OmniAPK delivers an all-in-one ecosystem augmented by a **Multi-Cloud AI Engine** with multi-key rotation, auto-routing, resilient rate-limit queueing, and an **Autonomous Agent** with full app manipulation capabilities.

```
+-----------------------------------------------------------------------------------------------+
|                                  ⚡ OmniAPK Studio & AI Suite                                 |
+-----------------------------------------------------------------------------------------------+
|   [1] Apktool       | Smali Disassembler/Assembler, Resource Decoding, Rebuilding             |
|   [2] Apktool M     | Ultra-fast In-Place Manifest Modder & Mobile Anti-Signature Engine       |
|   [3] APK Editor    | Resource/Asset Replacer, Permission Stripper, Package Cloner            |
|   [4] Lucky Patcher | Ad Stripper, In-App Billing (v2-v7) Bypass, LVL License, Root Spoof     |
|   [5] JADX / GUI    | Dalvik -> Java AST Decompiler, XREF Cross-Referencing, Obfuscation Map  |
|   [6] Frida         | Universal SSL Unpinning, Root Hide, Runtime Method Hook Generator        |
|   [7] MT Manager    | Anti-Split APK Merger (.apks/.xapk -> Standalone), Multi-DEX Regex, Diff|
|   [8] Game Guardian | Process RAM Memory Scanner, Value Freezer, Speedhack, Lua Script Gen    |
+-----------------------------------------------------------------------------------------------+
|                                   🤖 Cloud AI Orchestrator                                    |
|   * Multi-Cloud: OpenAI (GPT-4o/o1/o3), Anthropic (Claude 3.5), Gemini, Groq, DeepSeek, Ollama|
|   * Dynamic Key Pooling & Load Balancing | Auto-Routing | 429 Non-Terminating Cooldown Queue  |
|   * Autonomous AI Agent: Full control to decompile, patch bytecode, modify XML, & re-sign    |
+-----------------------------------------------------------------------------------------------+
```

---

## 🔬 Breakdown of the 8 Reconstructed Tools

| # | Tool | Original Role | OmniAPK Reconstruction & Enhancement |
|---|---|---|---|
| **1** | **Apktool** | CLI decode & rebuild of resources / smali | Pure-Python DEX/AXML/ARSC pipeline + seamless external binary fallback. Multi-dex extraction to `smali/` trees. |
| **2** | **Apktool M** | Fast mobile in-place quick editing & signing | In-memory `AndroidManifest.xml` and bytecode modification without full decompile overhead; instant V1/V2 re-signing. |
| **3** | **APK Editor (AEE)** | Interactive resource & permission editing | Comprehensive Asset, Drawable, Audio, and Raw JSON/XML explorer; 1-click permission manager; app cloner. |
| **4** | **Lucky Patcher** | Bytecode pattern patching & purchase bypass | Heuristic Dalvik opcode patcher for AdMob/Unity/AppLovin ads, Google Play Billing (v2-v7), LVL license, and root detection. |
| **5** | **JADX / JADX-GUI** | DEX to Java decompilation & code search | Pure-Python Dalvik bytecode to Java AST synthesizer; cross-reference (XREF) callers and string tracking. |
| **6** | **Frida** | Dynamic instrumentation & runtime hooking | Universal SSL Pinning bypass (OkHttp, TrustManager, Conscrypt, WebView), universal root bypass, and custom JS hooks. |
| **7** | **MT Manager** | DEX Editor++ and Anti-Split APK merger | Anti-Split APK merger (`.apks`, `.xapk`, `.apkm` -> unified APK); Batch Multi-DEX regex search/replace; side-by-side APK Differ. |
| **8** | **Game Guardian** | RAM memory scanning & freeze engine | Simulated/Live process RAM scanner (Dword, Float, Double, Byte, Xor), memory freeze/write daemon, speedhack, and `.lua` script generator. |

---

## 🤖 Multi-Cloud AI Engine & Autonomous Agent

### 1. Multi-Cloud Provider Support
- **OpenAI**: GPT-4o, GPT-4o-mini, o1, o3-mini
- **Anthropic Claude**: Claude 3.5 Sonnet, Claude 3.5 Haiku, Claude 3 Opus
- **Google Gemini**: Gemini 1.5 Pro, Gemini 1.5 Flash, Gemini 2.0
- **Groq**: Llama 3.3 70B Versatile, Llama 3.1 8B, DeepSeek R1 Distill
- **DeepSeek**: DeepSeek V3, DeepSeek R1
- **Mistral AI**: Mistral Large, Codestral
- **OpenRouter**: Unified access to 100+ AI models
- **Custom / Local AI**: Local Ollama (`http://localhost:11434/v1`), vLLM, LM Studio, or custom OpenAI-compatible endpoints.

### 2. Multi-API Key Pooling & Dynamic Auto-Routing
- Configure multiple API keys per provider in a dynamic round-robin pool.
- Intelligent task routing: dispatches code analysis to top coding models and fast regex classification to high-throughput models.

### 3. Rate-Limit Resiliency (Zero-Crash Guarantee)
- When a `429 Too Many Requests`, quota exhaustion, or TPM/RPM limit is encountered:
  1. **NEVER terminates or crashes the user's task**.
  2. Automatically marks the key for cooldown and rotates to the next available key.
  3. Cascades seamlessly to fallback providers in the priority chain.
  4. If all providers are cooling down, enters an **exponential backoff wait queue with real-time countdown progress** until service resumes.

### 4. Autonomous Modding Agent (Full App Control)
The AI Agent has direct tool-calling execution access to:
- `inspect_apk()` & `read_manifest()`
- `decompile_apk()` & `decompile_to_java()`
- `patch_method_return_value(class, method, return_val)` (Smali & Bytecode)
- `modify_manifest(debuggable, permissions, package_name)`
- `apply_lucky_patch(ads, billing, license, root)`
- `merge_split_apks(split_list, output_apk)`
- `generate_frida_suite()` & `generate_game_cheat_script()`
- `sign_apk_file()` (V1 JAR + V2 APK Signature Scheme + 4-Byte ZipAlign)

---

## 🚀 Dual-Platform Installation & Quickstart

### 🐧 System A: Linux (Ubuntu / Debian / Arch / Fedora / Kali / WSL / Servers)

```bash
# 1. Clone repository
git clone https://github.com/nyadaryt5/Apk-modifyer-.git
cd Apk-modifyer-

# 2. Run 1-click Linux installer
chmod +x install-linux.sh
./install-linux.sh

# 3. Launch Web Studio (Binding to 0.0.0.0:8000 for preview & desktop use)
python3 main.py

# 4. Or use the Interactive CLI
./cli.py --help
```

---

### 📱 System B: Android (Termux)

```bash
# 1. Inside Termux app, run the Termux installer
chmod +x install-termux.sh
./install-termux.sh

# 2. Start the Mobile Studio server
python3 main.py

# 3. Open your mobile browser at:
# http://localhost:8000
```

---

## 💻 CLI Usage Guide (`omniapk` / `apkmod`)

```bash
# Inspect APK Structure
omniapk inspect app.apk

# Apply Lucky Patcher Mods (Ad Removal, VIP/Billing Bypass, Root Hide, V1+V2 Sign)
omniapk lucky-patch app.apk -o app_modded.apk

# Run Autonomous AI Agent Mod Task
omniapk ai-mod app.apk --prompt "Unlock all VIP features, strip AdMob ads, enable debuggable, and sign"

# Apktool M Quick Manifest Mod
omniapk quick-mod app.apk --package com.new.pkg --debuggable --strip-ads

# Decompile APK to Smali and Java AST
omniapk decompile app.apk -o ./decompiled_project

# MT Manager Anti-Split APK Merger
omniapk split-merge base.apk split_config.arm64.apk split_config.xxhdpi.apk -o standalone.apk

# Diff Two APKs
omniapk diff original.apk modded.apk

# Generate Frida Dynamic Hook Scripts
omniapk frida-gen --class-name com.target.app.MainActivity --method-name isPremium --return-val true -o hook.js

# Generate Game Guardian Lua Cheat Script
omniapk gg-gen --game "MyGame" --search 100 --set-value 999999 --speed 2.0 -o cheat.lua

# Sign APK with V1 + V2 Test Key
omniapk sign app.apk -o app_signed.apk

# Start Web Studio
omniapk serve --host 0.0.0.0 --port 8000
```

---

## 📂 Project Architecture

```
Apk-modifyer-/
├── cli.py                              # Unified Rich CLI Suite (`omniapk`)
├── main.py                             # Web Studio & API entrypoint
├── install-linux.sh                    # 1-Click Linux Installer
├── install-termux.sh                   # 1-Click Android Termux Installer
├── requirements.txt                    # Dependencies
│
├── omniapk/                            # Core Framework Package
│   ├── config.py                       # Platform detection & tool paths
│   │
│   ├── core/                           # Pure-Python Binary Parsers & Signers
│   │   ├── dex_parser.py               # DEX header, strings, types, bytecode disassembler
│   │   ├── dex_editor.py               # Dalvik opcode patcher, string replacer, Adler32/SHA1
│   │   ├── axml_parser.py              # Android Binary XML (AXML) decoder
│   │   ├── axml_editor.py              # In-place manifest modifier (permissions, flags)
│   │   ├── arsc_parser.py              # resources.arsc parser & string pool editor
│   │   ├── apk_packager.py             # Unpacker, repacker, 4-byte zipaligner
│   │   └── apk_signer.py               # V1 (JAR) + V2 (APK Signature Block) signer
│   │
│   ├── modules/                        # Reconstructed 8 Modding Engines
│   │   ├── apktool/                    # [Tool 1] Smali & Resource decompiler/builder
│   │   ├── apktool_m/                  # [Tool 2] Rapid in-place manifest & sigkiller
│   │   ├── apk_editor/                 # [Tool 3] Asset explorer, cloner, permission stripper
│   │   ├── lucky_patcher/              # [Tool 4] AdMob/Billing/LVL/Root heuristic patchers
│   │   ├── jadx/                       # [Tool 5] Java AST decompiler & XREF tracer
│   │   ├── frida/                      # [Tool 6] SSL unpinning & runtime hook generator
│   │   ├── mt_manager/                 # [Tool 7] Anti-Split merger, Multi-DEX regex & differ
│   │   └── game_guardian/              # [Tool 8] RAM memory scanner, freezer & Lua builder
│   │
│   ├── ai/                             # Multi-Cloud AI Engine & Autonomous Agent
│   │   ├── providers/                  # OpenAI, Claude, Gemini, Groq, DeepSeek, Custom
│   │   ├── router.py                   # Key pool, auto-routing & priority fallback
│   │   ├── rate_limiter.py             # 429 Backoff queue & task non-termination manager
│   │   ├── tools.py                    # Complete autonomous agent tool registry
│   │   └── agent.py                    # Autonomous prompt-driven modding controller
│   │
│   ├── server/                         # FastAPI & WebSocket Server
│   │   └── app.py                      # REST endpoints & real-time log broadcaster
│   │
│   └── web/                            # Responsive Web Studio (Desktop & Mobile)
│       ├── index.html                  # Cyberpunk dark glassmorphism SPA
│       ├── css/style.css               # Responsive styling
│       └── js/app.js                   # Client controller & WebSocket handler
│
├── tests/                              # Automated Unit & Integration Tests (24/24 passing)
│   ├── test_parsers.py
│   ├── test_lucky_patcher.py
│   ├── test_frida_gg.py
│   ├── test_split_merger.py
│   ├── test_ai_router.py
│   └── test_api.py
└── samples/                            # Sample target APK & synthetic generator
```

---

## 🧪 Automated Test Suite

Run the full automated test suite:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Output:
```
----------------------------------------------------------------------
Ran 24 tests in 0.831s

OK
```

---

## 🔒 Security and Legal Notice

OmniAPK Studio is designed for software developers, security analysts, and mobile application researchers for authorized security auditing, debugging, and reverse engineering. Always ensure you have appropriate authorization before testing third-party software.
