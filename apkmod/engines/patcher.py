"""Analysis engine -- the fourth slot, filled with reporting instead of bypasses.

Lucky Patcher's headline features are "remove licence verification" and "patch
out the check". This toolkit does the *diagnostic* half of that and stops: it
tells you where a build protects itself, which SDKs phone home, which
permissions are sensitive, and whether the signature is intact. That is the
part you need for interoperability work, security review, or fixing your own
app.

What is deliberately **not** here: defeating licence checks, unlocking paid
features, forging signatures of someone else's app, or altering a live
service's entitlements. If that is the goal, this is the wrong tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from ..analyze import Report, analyze_apk
from ..signing import verify_v1
from .base import Engine, EngineStatus

__all__ = ["PatcherEngine", "TamperReport"]

DISCLAIMER = (
    "Analysis only: this reports protections, it does not remove them. "
    "Bypassing licence checks or server-side entitlements is out of scope."
)


@dataclass
class TamperReport:
    apk: str
    protections: List[str]
    ad_sdks: List[str]
    trackers: List[str]
    signature_status: dict
    verdict: str

    def as_dict(self) -> dict:
        return {
            "apk": self.apk,
            "protections": self.protections,
            "ad_sdks": self.ad_sdks,
            "trackers": self.trackers,
            "signature": self.signature_status,
            "verdict": self.verdict,
            "notice": DISCLAIMER,
        }

    def as_text(self) -> str:
        def block(title: str, items: list[str]) -> list[str]:
            body = [f"  - {item}" for item in items] or ["  - none identified"]
            return [f"{title}:"] + body

        lines = [
            f"Tamper surface: {self.apk}",
            "-" * min(70, len(self.apk) + 16),
            f"signature: v1={self.signature_status.get('v1_valid')} "
            f"mismatched={len(self.signature_status.get('mismatched', []))} "
            f"uncovered={len(self.signature_status.get('unsigned', []))}",
            "",
        ]
        lines += block("protections found", self.protections) + [""]
        lines += block("ad sdks", self.ad_sdks) + [""]
        lines += block("analytics / trackers", self.trackers) + [""]
        lines += [f"verdict: {self.verdict}", "", DISCLAIMER]
        return "\n".join(lines)


TRACKER_WORDS = (
    "firebase", "crashlytics", "flurry", "amplitude", "mixpanel", "appsflyer",
    "adjust", "onesignal", "branch", "sentry", "facebook",
)
AD_WORDS = (
    "admob", "google mobile ads", "unity ads", "applovin", "ironsource",
    "vungle", "chartboost", "mintegral", "startapp", "inmobi", "facebook audience network",
)


class PatcherEngine(Engine):
    name = "patcher"
    label = "Protection analysis (Lucky-Patcher slot, analysis only)"
    description = "Report what an APK protects and what it phones home about."
    capabilities = ["anti-tamper report", "ad/tracker inventory", "signature verification", "permission audit"]

    def status(self) -> EngineStatus:
        return EngineStatus(
            name=self.name,
            label=self.label,
            available=True,
            description=self.description,
            version="native",
            location="apkmod.analyze / apkmod.signing",
            capabilities=self.capabilities,
            notes=[DISCLAIMER],
        )

    def scan(self, apk: Path) -> TamperReport:
        report: Report = analyze_apk(apk)
        verify = verify_v1(apk)
        ad_sdks = [s for s in report.sdk if any(w in s.lower() for w in AD_WORDS)]
        trackers = [s for s in report.sdk if any(w in s.lower() for w in TRACKER_WORDS)]
        verdict = self._verdict(report, verify)
        return TamperReport(
            apk=str(apk),
            protections=report.integrity,
            ad_sdks=ad_sdks,
            trackers=trackers,
            signature_status={
                "v1_present": verify.signed,
                "v1_valid": verify.signature_valid,
                "mismatched": verify.mismatched,
                "unsigned": verify.unsigned,
                "problems": verify.problems,
                "certificate": verify.certificate_sha256,
            },
            verdict=verdict,
        )

    @staticmethod
    def _verdict(report: Report, verify) -> str:
        if report.integrity:
            return (
                "this build checks itself - edits will be detected at runtime; expect the app to "
                "refuse to start rather than to run modified"
            )
        if verify.signed and verify.signature_valid is False:
            return "the signature does not verify: the archive was edited after signing"
        if not verify.signed:
            return "no v1 signature found; the APK is either v2-only or unsigned"
        return "no obvious self-checks; a modified build would still need a valid signature to install"
