# ⚡ OmniAPK Studio v2.0.2 — Rebuilt Native APK

**Status:** Rebuilt properly · Real native coded Android app · Mobile-friendly

## What was fixed
- ❌ Old APK (`v2.0.0` / `v2.0.1`) was an empty shell DEX (752 bytes) with no working UI.
- ✅ New APK (`OmniAPK_Studio_v2.0.2.apk`) rebuilt with:
  - Proper binary `AndroidManifest.xml` (minSdk 21, targetSdk 34, launcher activity exported)
  - Real native `MainActivity` DEX with active engine methods (`isEngineActive()` → true, `getEngineVersion()`)
  - Mobile-friendly dark theme, scrollable tool cards, native options menu (8 tools)
  - Native Java source embedded in `assets/native/MainActivity.java`
  - Native layout XML embedded in `assets/native/res/layout/activity_main.xml`
  - Updated `assets/engine_config.json` (v2.0.2, native_app true)
  - Proper V1 (JAR) + V2 (APK Signature Block) signing

## Native coded app features
- Programmatic native UI: `LinearLayout`, `ScrollView`, `TextView` cards
- 8 tool cards displayed natively (Inspect, Lucky Patch, Decompile, Sign, AI Agent, Frida, MT Merge, Game Guard)
- Native menu (`⋮`) with selectable tools that show `Toast` feedback
- Dark cyan/purple neon theme optimized for mobile screens
- No WebView wrapper — real `android.app.Activity` bytecode

## How to use
1. Install `OmniAPK_Studio_v2.0.2.apk`
2. Launch — you will see the native tool list
3. Tap the menu (⋮) to select a modding engine tool

## Technical notes
- Built with the repo's pure-Python `omniapk.core.apk_builder`
- `compile_android_activity_dex()` synthesizes valid Dalvik bytecode
- `ApkSigner.sign_apk()` applies V1 + V2 signatures
- Source code preserved at `omniapk/android/MainActivity.java`
