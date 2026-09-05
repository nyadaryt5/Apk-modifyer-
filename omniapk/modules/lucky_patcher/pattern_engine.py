"""
Module 4: Lucky Patcher - Unified Multi-Target Patching Pipeline.
Combines Ad Removal, Billing Emulation, LVL Bypass, Root Detection Bypass,
Signature Verification Killing, and Custom User Patch Recipes.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from omniapk.modules.lucky_patcher.ad_remover import AdRemover
from omniapk.modules.lucky_patcher.billing_bypass import BillingBypass
from omniapk.modules.lucky_patcher.license_bypass import LicenseBypass
from omniapk.core.apk_signer import ApkSigner

class LuckyPatcherEngine:
    """Orchestrates comprehensive Lucky Patcher operations."""

    @staticmethod
    def apply_auto_patch(
        apk_path: str | Path,
        output_apk: str | Path,
        remove_ads: bool = True,
        bypass_billing: bool = True,
        bypass_license: bool = True,
        bypass_root_checks: bool = True,
        sign: bool = True
    ) -> Dict[str, Any]:
        """Apply all selected Lucky Patcher mods in sequence and sign the result."""
        apk_path = Path(apk_path)
        output_apk = Path(output_apk)

        cur_apk = apk_path
        results = {
            "ads": None,
            "billing": None,
            "license": None,
            "signed": False,
            "output_apk": str(output_apk)
        }

        temp_step_1 = output_apk.with_suffix(".step1.tmp.apk")
        temp_step_2 = output_apk.with_suffix(".step2.tmp.apk")

        try:
            # Step 1: Ads
            if remove_ads:
                res_ads = AdRemover.patch_apk(cur_apk, temp_step_1)
                results["ads"] = res_ads
                cur_apk = temp_step_1

            # Step 2: Billing
            if bypass_billing:
                out_target = temp_step_2 if cur_apk == temp_step_1 else temp_step_1
                res_bill = BillingBypass.patch_apk(cur_apk, out_target)
                results["billing"] = res_bill
                cur_apk = out_target

            # Step 3: License & Root
            if bypass_license or bypass_root_checks:
                out_target = temp_step_1 if cur_apk == temp_step_2 else temp_step_2
                res_lic = LicenseBypass.patch_apk(cur_apk, out_target)
                results["license"] = res_lic
                cur_apk = out_target

            # Step 4: Final Sign & Output
            if sign:
                ApkSigner.sign_apk(cur_apk, output_apk)
                results["signed"] = True
            else:
                if output_apk.exists():
                    output_apk.unlink()
                cur_apk.rename(output_apk)

        finally:
            # Clean up intermediate steps
            if temp_step_1.exists():
                temp_step_1.unlink()
            if temp_step_2.exists():
                temp_step_2.unlink()

        results["success"] = True
        results["size_bytes"] = output_apk.stat().st_size
        return results
