"""
Module 4: Lucky Patcher - In-App Billing & Subscription Bypass Engine.
Emulates Google Play Billing responses (v2/v3/v4/v5/v6/v7) and forces purchase status to True.
"""

import zipfile
import re
from pathlib import Path
from typing import Dict, Any, List

from omniapk.core.dex_editor import DexEditor

BILLING_CLASSES = [
    "com/android/vending/billing/IInAppBillingService",
    "com/android/billingclient/api/BillingClient",
    "com/android/billingclient/api/Purchase",
    "com/android/billingclient/api/BillingResult",
    "com/android/billingclient/api/Purchase$PurchasesResult",
]

PREMIUM_METHOD_PATTERNS = [
    "isPremium",
    "isPro",
    "isSubscribed",
    "isVip",
    "hasPurchased",
    "isPurchased",
    "isPaidUser",
    "isLicenseValid",
    "checkSubscription",
    "isAdRemoved",
    "isUnlocked",
    "getIsPremium",
    "getIsPro",
    "getIsSubscribed"
]

class BillingBypass:
    """Bypasses Google Play Billing and forces VIP/Premium boolean flags."""

    @staticmethod
    def patch_apk(apk_path: str | Path, output_apk: str | Path) -> Dict[str, Any]:
        """Search and patch all billing validation and premium check methods."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)
        temp_apk = output_apk.with_suffix(".billing.tmp.apk")

        methods_patched = []

        with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(temp_apk, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                if item.filename.startswith("META-INF/"):
                    continue

                if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                    dex_data = src.read(item.filename)
                    editor = DexEditor(dex_data)
                    parser = editor.parser

                    for cls in parser.classes:
                        for m in cls.get("virtual_methods", []) + cls.get("direct_methods", []):
                            m_name = m["name"]
                            # Check if method matches any premium getter pattern
                            if any(p.lower() == m_name.lower() or (p.lower() in m_name.lower() and len(m_name) < 25) for p in PREMIUM_METHOD_PATTERNS):
                                # Patch return true
                                if editor.patch_method_return_true(cls["name"], m_name):
                                    methods_patched.append(f"{cls['name']}->{m_name}()")

                    editor.recalculate_checksums()
                    dst.writestr(item, editor.get_bytes())
                else:
                    dst.writestr(item, src.read(item.filename))

        if output_apk.exists():
            output_apk.unlink()
        temp_apk.rename(output_apk)

        return {
            "success": True,
            "methods_patched_count": len(methods_patched),
            "patched_methods": methods_patched,
            "output_apk": str(output_apk)
        }
