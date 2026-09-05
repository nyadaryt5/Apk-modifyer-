"""
Module 4: Lucky Patcher - Ad Remover Engine.
Identifies and eliminates advertising SDKs (AdMob, Unity, AppLovin, IronSource, Vungle, InMobi)
by disabling ad components in the Manifest and neutralizing bytecode invocation points.
"""

import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional

from omniapk.core.axml_editor import AxmlEditor
from omniapk.core.dex_editor import DexEditor
from omniapk.core.dex_parser import DexParser

# Ad SDK Known Signatures
AD_SDK_CLASSES = [
    "com/google/android/gms/ads",
    "com/google/ads",
    "com/unity3d/ads",
    "com/unity3d/services/ads",
    "com/applovin",
    "com/ironsource/mediationsdk",
    "com/vungle/warren",
    "com/inmobi/ads",
    "com/mbridge/msdk",
    "com/chartboost/sdk",
    "com/bytedance/sdk/openadsdk",
    "com/facebook/ads",
    "com/startapp/sdk"
]

AD_MANIFEST_COMPONENTS = [
    "com.google.android.gms.ads.AdActivity",
    "com.google.android.gms.ads.AdService",
    "com.unity3d.services.ads.adunit.AdUnitActivity",
    "com.applovin.adview.AppLovinInterstitialActivity",
    "com.ironsource.mediationsdk.IronSource",
    "com.vungle.warren.ui.VungleActivity"
]

AD_METHOD_NAMES = [
    "loadAd",
    "showAd",
    "showInterstitial",
    "showRewardedVideo",
    "loadInterstitial",
    "loadBanner",
    "showBanner",
    "showRewardVideo",
    "displayAd"
]

class AdRemover:
    """Automated Ad stripping and neutralizing engine."""

    @staticmethod
    def patch_apk(apk_path: str | Path, output_apk: str | Path) -> Dict[str, Any]:
        """Strip ad permissions, remove ad activities from manifest, and stub ad methods in DEX."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".noads.tmp.apk")

        manifest_modified = False
        removed_ad_perms = []
        dex_methods_patched = 0

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue

                if item.filename == "AndroidManifest.xml":
                    editor = AxmlEditor(src.read(item.filename))
                    removed_ad_perms = editor.remove_ad_permissions()
                    # Remove Ad Activities and Meta-data
                    editor.xml_text = re.sub(
                        r'<activity[^>]*android:name="(?:com\.google\.android\.gms\.ads|com\.unity3d|com\.applovin)[^"]*"[^>]*/>\s*',
                        '',
                        editor.xml_text
                    )
                    editor.xml_text = re.sub(
                        r'<meta-data[^>]*android:name="com\.google\.android\.gms\.ads\.APPLICATION_ID"[^>]*/>\s*',
                        '',
                        editor.xml_text
                    )
                    dst.writestr("AndroidManifest.xml", editor.get_xml().encode("utf-8"))
                    manifest_modified = True

                elif item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    dex_data = src.read(item.filename)
                    editor = DexEditor(dex_data)
                    parser = editor.parser
                    
                    # Search for Ad classes and stub their show/load methods
                    for cls in parser.classes:
                        is_ad_class = any(ad_sig in cls["name"] for ad_sig in AD_SDK_CLASSES)
                        for m in cls.get("virtual_methods", []) + cls.get("direct_methods", []):
                            m_name = m["name"]
                            if m_name in AD_METHOD_NAMES or (is_ad_class and ("show" in m_name.lower() or "load" in m_name.lower())):
                                if editor.patch_method_return_void(cls["name"], m_name):
                                    dex_methods_patched += 1

                    editor.recalculate_checksums()
                    dst.writestr(item, editor.get_bytes())

                else:
                    dst.writestr(item, src.read(item.filename))

        if output_apk.exists():
            output_apk.unlink()
        temp_apk.rename(output_apk)

        return {
            "success": True,
            "manifest_cleaned": manifest_modified,
            "ad_permissions_removed": removed_ad_perms,
            "dex_ad_methods_neutralized": dex_methods_patched,
            "output_apk": str(output_apk)
        }
