"""Static analysis: turn an APK into a readable report.

This is the reporting half of the toolkit. It tells you *what* an app does --
which ad/analytics SDKs it embeds, which permissions it asks for, whether it
checks its own signature, whether it is debuggable, which hosts it talks to.

It deliberately stops at reporting. Nothing here patches out a licence check,
removes a payment gate, or unlocks anything in a live service; see README.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from .apk import ApkContainer
from .asn1 import ApkModError
from .dex import iter_dex_strings

__all__ = ["analyze_apk", "SDK_SIGNATURES", "DANGEROUS_PERMISSIONS"]

SDK_SIGNATURES: Dict[str, tuple[str, ...]] = {
    "AdMob / Google Mobile Ads": ("com.google.android.gms.ads", "AdView", "admob"),
    "Facebook Audience Network": ("com.facebook.ads", "facebook.audience"),
    "Unity Ads": ("com.unity3d.services.ads", "UnityAds"),
    "AppLovin": ("com.applovin", "applovin"),
    "ironSource": ("com.ironsource", "ironsource"),
    "Vungle": ("com.vungle", "vungle"),
    "Chartboost": ("com.chartboost", "chartboost"),
    "Mintegral": ("com.mbridge", "mintegral"),
    "Startapp": ("com.startapp", "startapp"),
    "InMobi": ("com.inmobi", "inmobi"),
    "Firebase": ("com.google.firebase", "firebase"),
    "Crashlytics": ("crashlytics", "io.fabric"),
    "Flurry": ("com.flurry", "flurry"),
    "Amplitude": ("com.amplitude", "amplitude"),
    "Mixpanel": ("com.mixpanel", "mixpanel"),
    "Sentry": ("io.sentry", "sentry"),
    "AppsFlyer": ("com.appsflyer", "appsflyer"),
    "Adjust": ("com.adjust", "adjust.sdk"),
    "OneSignal": ("com.onesignal", "onesignal"),
    "Branch": ("io.branch.referral", "branch.io"),
    "Google Play Billing": ("com.android.billingclient", "BillingClient"),
    "Google Play Licensing (LVL)": ("com.google.android.vending.licensing", "LicenseChecker"),
    "Play Integrity / SafetyNet": ("com.google.android.play.core.integrity", "SafetyNet", "IntegrityManager"),
    "Facebook SDK": ("com.facebook.appevents", "com.facebook.FacebookSdk"),
    "OkHttp": ("okhttp3", "com.squareup.okhttp"),
    "Retrofit": ("retrofit2", "com.squareup.retrofit"),
    "Glide": ("com.bumptech.glide",),
    "Room": ("androidx.room", "android.arch.persistence.room"),
    "React Native": ("com.facebook.react", "libreactnativejni.so"),
    "Flutter": ("io.flutter", "libflutter.so"),
    "Unity engine": ("com.unity3d.player", "libunity.so"),
    "Cocos2d": ("org.cocos2dx", "libcocos2d"),
    "Godot": ("org.godotengine", "libgodot"),
    "Cordova / PhoneGap": ("org.apache.cordova",),
    "Xamarin": ("mono.android", "Xamarin"),
    "Kotlin coroutines": ("kotlinx.coroutines",),
    "OpenSSL (native crypto)": ("libssl.so", "libcrypto.so"),
    "Root detection libs": ("com.scottyab.rootbeer", "RootBeer", "su/bin", "/system/xbin/su"),
    "Emulator detection": ("isEmulator", "generic_x86", "goldfish", "ranchu"),
    "Frida / hooking detection": ("frida", "xposed", "substrate", "libfrida"),
}

# Markers that suggest the app verifies its own integrity before it will run.
# Any single hit counts, so these are deliberately specific strings.
INTEGRITY_MARKERS: Dict[str, tuple[str, ...]] = {
    "reads its own signature": (
        "GET_SIGNATURES",
        "GET_SIGNING_CERTIFICATES",
        "signingInfo",
        "Landroid/content/pm/Signature;",
    ),
    "hashes data (possible signature compare)": ("MessageDigest",),
    "checks the installer source": ("getInstallerPackageName", "getInstallSourceInfo"),
    "licence verification": ("LicenseChecker", "com.google.android.vending.licensing"),
    "anti-tamper / native checks": ("checkSignature", "libverify", "libtamper"),
}

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}

_URL_RX = re.compile(r"https?://[A-Za-z0-9._~%\-]+(?::\d+)?(?:/[^\s\"'<>\\]*)?")
_SECRET_RX = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|bearer)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
)
_HOST_RX = re.compile(r"^[a-z0-9][a-z0-9.\-]{2,}\.(com|net|org|io|dev|app|co|ru|cn|in|de|uk|fr|br|jp|me|ai|xyz|info|biz)$")


@dataclass
class Finding:
    category: str
    title: str
    detail: str
    severity: str = "info"  # info | notice | warning


@dataclass
class Report:
    apk: str
    manifest: dict
    facts: dict
    sdk: List[str]
    integrity: List[str]
    findings: List[Finding]
    hosts: List[str]
    possible_secrets: List[str]
    dex_stats: dict

    def as_dict(self) -> dict:
        return {
            "apk": self.apk,
            "manifest": self.manifest,
            "facts": {k: v for k, v in self.facts.items() if k != "manifest"},
            "sdk": self.sdk,
            "integrity_checks": self.integrity,
            "findings": [f.__dict__ for f in self.findings],
            "network_hosts": self.hosts,
            "possible_secrets": self.possible_secrets,
            "dex": self.dex_stats,
        }

    def as_markdown(self) -> str:
        lines = [f"# APK analysis: `{self.apk}`", ""]
        manifest = self.manifest
        lines += [
            "## Identity",
            "",
            f"- **package:** `{manifest.get('package')}`",
            f"- **versionName / versionCode:** {manifest.get('version_name')} / {manifest.get('version_code')}",
            f"- **minSdk / targetSdk:** {manifest.get('min_sdk')} / {manifest.get('target_sdk')}",
            f"- **size:** {self.facts.get('file_size_human')} ({self.facts.get('entry_count')} entries)",
            f"- **dex files:** {', '.join(self.facts.get('dex_files', [])) or 'none'}",
            "",
            "## Signing",
            "",
        ]
        signing = self.facts.get("signing", {})
        lines.append(f"- v1 (JAR): **{signing.get('v1_jar_signing')}**")
        lines.append(f"- v2: **{signing.get('v2')}** | v3: **{signing.get('v3')}** | v4: **{signing.get('v4')}**")
        for cert in signing.get("certificates", []):
            lines.append(f"- cert `{cert['subject_cn'] or 'unknown'}` sha256 `{cert['sha256'][:32]}...`")
        lines += ["", "## Permissions", ""]
        permissions = manifest.get("permissions", [])
        if not permissions:
            lines.append("- none declared")
        for permission in permissions:
            mark = " **[dangerous]**" if permission in DANGEROUS_PERMISSIONS else ""
            lines.append(f"- `{permission}`{mark}")
        lines += ["", "## Components", ""]
        for key in ("activities", "services", "receivers", "providers"):
            values = manifest.get(key, [])
            lines.append(f"- **{key}:** {len(values)}")
        if manifest.get("launcher_activity"):
            lines.append(f"- **launcher:** `{manifest['launcher_activity']}`")
        if manifest.get("exported_components"):
            lines.append("- **exported:** " + ", ".join(f"`{c}`" for c in manifest["exported_components"]))
        lines += ["", "## SDKs detected", ""]
        for name in self.sdk or ["none identified"]:
            lines.append(f"- {name}")
        lines += ["", "## Integrity / anti-tamper indicators", ""]
        for name in self.integrity or ["none identified"]:
            lines.append(f"- {name}")
        lines += ["", "## Network hosts referenced in code", ""]
        for host in self.hosts[:40] or ["none found"]:
            lines.append(f"- `{host}`")
        if self.possible_secrets:
            lines += ["", "## Possible hard-coded secrets", ""]
            for item in self.possible_secrets[:20]:
                lines.append(f"- `{item}`")
        lines += ["", "## Findings", ""]
        for finding in self.findings:
            lines.append(f"- **[{finding.severity}]** {finding.title} - {finding.detail}")
        lines += [
            "",
            "---",
            "",
            "*Analysis only. This toolkit reports what an app does; it does not defeat licence",
            "checks, payment gates or server-side entitlements.*",
        ]
        return "\n".join(lines)

    def as_text(self) -> str:
        manifest = self.manifest
        out = [
            f"APK analysis: {self.apk}",
            "=" * min(72, len(self.apk) + 14),
            f"package        : {manifest.get('package')}",
            f"version        : {manifest.get('version_name')} ({manifest.get('version_code')})",
            f"sdk            : min {manifest.get('min_sdk')} / target {manifest.get('target_sdk')}",
            f"size           : {self.facts.get('file_size_human')} in {self.facts.get('entry_count')} entries",
            f"dex            : {len(self.facts.get('dex_files', []))} file(s)",
            f"debuggable     : {manifest.get('debuggable')}",
        ]
        signing = self.facts.get("signing", {})
        out.append(f"signing        : v1={signing.get('v1_jar_signing')} v2={signing.get('v2')} v3={signing.get('v3')}")
        for cert in signing.get("certificates", []):
            out.append(f"cert           : {cert['subject_cn'] or 'unknown'} sha256={cert['sha256'][:32]}...")
        out.append("")
        out.append(f"permissions ({len(manifest.get('permissions', []))}):")
        for permission in manifest.get("permissions", []):
            flag = " [dangerous]" if permission in DANGEROUS_PERMISSIONS else ""
            out.append(f"  - {permission}{flag}")
        out.append("")
        out.append("components:")
        for key in ("activities", "services", "receivers", "providers"):
            out.append(f"  {key:<10}: {len(manifest.get(key, []))}")
        if manifest.get("launcher_activity"):
            out.append(f"  launcher    : {manifest['launcher_activity']}")
        out.append("")
        out.append(f"sdks ({len(self.sdk)}): " + (", ".join(self.sdk) if self.sdk else "none identified"))
        out.append(f"integrity     : " + (", ".join(self.integrity) if self.integrity else "none identified"))
        if self.hosts:
            out.append("")
            out.append(f"hosts ({len(self.hosts)}): " + ", ".join(self.hosts[:20]))
        if self.possible_secrets:
            out.append("")
            out.append(f"possible secrets ({len(self.possible_secrets)}):")
            for item in self.possible_secrets[:10]:
                out.append(f"  - {item}")
        if self.findings:
            out.append("")
            out.append("findings:")
            for finding in self.findings:
                out.append(f"  [{finding.severity:<7}] {finding.title}: {finding.detail}")
        return "\n".join(out)


def analyze_apk(apk: Path, *, max_strings: int = 200000) -> Report:
    apk = Path(apk)
    findings: List[Finding] = []
    with ApkContainer(apk) as container:
        facts = container.facts()
        manifest = facts.get("manifest", {})
        if "manifest_error" in facts:
            findings.append(
                Finding("manifest", "manifest unreadable", facts["manifest_error"], "warning")
            )
        try:
            strings = iter_dex_strings(container.dex_blobs())
        except ApkModError as exc:
            strings = iter_dex_strings([])
            findings.append(Finding("dex", "dex unreadable", str(exc), "warning"))

        haystack = "\n".join(strings.strings[:max_strings])
        haystack_lower = haystack.lower()
        descriptor_blob = "\n".join(strings.type_descriptors).lower()

        sdk = sorted(
            name
            for name, markers in SDK_SIGNATURES.items()
            if any(marker.lower() in haystack_lower or marker.lower() in descriptor_blob for marker in markers)
        )
        integrity = sorted(
            label
            for label, markers in INTEGRITY_MARKERS.items()
            if any(marker.lower() in haystack_lower for marker in markers)
        )

        hosts = sorted({m.group(0).split("/")[2].lower() for m in _URL_RX.finditer(haystack)})
        hosts += sorted({s.lower() for s in strings.strings if _HOST_RX.match(s.lower())})
        hosts = sorted(set(hosts))[:120]

        secrets = sorted(
            {f"{m.group(1)}={m.group(2)[:12]}..." for m in _SECRET_RX.finditer(haystack)}
        )[:40]

        # ---- findings --------------------------------------------------
        permissions = manifest.get("permissions", [])
        dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
        if dangerous:
            findings.append(
                Finding(
                    "permissions",
                    f"{len(dangerous)} runtime-sensitive permissions",
                    ", ".join(p.rsplit(".", 1)[-1] for p in dangerous),
                    "notice",
                )
            )
        if manifest.get("debuggable"):
            findings.append(
                Finding("manifest", "app is debuggable", "anyone with adb can attach a debugger", "warning")
            )
        if manifest.get("exported_components"):
            findings.append(
                Finding(
                    "manifest",
                    f"{len(manifest['exported_components'])} exported components",
                    "reachable from other apps via explicit intents",
                    "notice",
                )
            )
        signing = facts.get("signing", {})
        if not signing.get("v1_jar_signing") and not signing.get("v2"):
            findings.append(Finding("signing", "APK appears unsigned", "it will not install", "warning"))
        elif signing.get("v1_jar_signing") and not signing.get("v2") and not signing.get("v3"):
            findings.append(
                Finding(
                    "signing",
                    "v1-only signature",
                    "Android 11+ wants a v2/v3 signature; re-sign with apksigner for full coverage",
                    "notice",
                )
            )
        if integrity:
            findings.append(
                Finding(
                    "integrity",
                    "self-integrity checks present",
                    "editing this APK will likely break it at runtime: " + "; ".join(integrity),
                    "notice",
                )
            )
        libs = facts.get("native_libraries", {})
        if libs:
            findings.append(
                Finding("native", f"native code for {len(libs)} ABI(s)", ", ".join(sorted(libs)), "info")
            )
        if secrets:
            findings.append(
                Finding("secrets", f"{len(secrets)} possible hard-coded secrets", "rotate anything that is real", "warning")
            )

        dex_stats = {
            "string_count": len(strings.strings),
            "type_count": len(strings.type_descriptors),
            "dex_files": len(facts.get("dex_files", [])),
        }

    return Report(
        apk=str(apk),
        manifest=manifest,
        facts=facts,
        sdk=sdk,
        integrity=integrity,
        findings=findings,
        hosts=hosts,
        possible_secrets=secrets,
        dex_stats=dex_stats,
    )
