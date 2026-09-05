"""
Pure-Python Android Binary XML (AXML) Editor & Fast In-Place Modifier (Apktool M & APK Editor Core).
Enables quick permission stripping, debuggable injection, package renaming, and component updates.
"""

import re
from typing import List, Optional
from omniapk.core.axml_parser import AxmlParser

class AxmlEditor:
    """Manipulates AndroidManifest.xml both in decoded XML and binary representation."""
    def __init__(self, raw_or_text):
        if isinstance(raw_or_text, (bytes, bytearray)):
            self.raw_data = bytes(raw_or_text)
            self.parser = AxmlParser(self.raw_data)
            self.xml_text = self.parser.to_xml()
        else:
            self.xml_text = str(raw_or_text)
            self.parser = None
            self.raw_data = None

    def get_xml(self) -> str:
        """Get the current XML representation."""
        return self.xml_text

    def set_package_name(self, new_package: str) -> None:
        """Change the root package name."""
        self.xml_text = re.sub(
            r'(<manifest[^>]*package=")([^"]+)(")',
            rf'\g<1>{new_package}\g<3>',
            self.xml_text,
            count=1
        )

    def set_debuggable(self, enabled: bool = True) -> None:
        """Enable or disable android:debuggable attribute on <application>."""
        val = "true" if enabled else "false"
        if 'android:debuggable="' in self.xml_text:
            self.xml_text = re.sub(
                r'android:debuggable="[^"]*"',
                f'android:debuggable="{val}"',
                self.xml_text
            )
        else:
            self.xml_text = re.sub(
                r'(<application\b)',
                rf'\1 android:debuggable="{val}"',
                self.xml_text,
                count=1
            )

    def set_network_security_config(self, xml_ref: str = "@xml/network_security_config") -> None:
        """Inject network security config to bypass SSL pinning at OS level."""
        if 'android:networkSecurityConfig="' in self.xml_text:
            self.xml_text = re.sub(
                r'android:networkSecurityConfig="[^"]*"',
                f'android:networkSecurityConfig="{xml_ref}"',
                self.xml_text
            )
        else:
            self.xml_text = re.sub(
                r'(<application\b)',
                rf'\1 android:networkSecurityConfig="{xml_ref}"',
                self.xml_text,
                count=1
            )

    def remove_permission(self, permission_name: str) -> bool:
        """Remove a uses-permission entry."""
        pattern = rf'<uses-permission\s+android:name="{re.escape(permission_name)}"[^>]*/>\s*'
        new_text = re.sub(pattern, '', self.xml_text)
        changed = new_text != self.xml_text
        self.xml_text = new_text
        return changed

    def add_permission(self, permission_name: str) -> None:
        """Add a uses-permission entry if not already present."""
        if permission_name in self.xml_text:
            return
        tag = f'    <uses-permission android:name="{permission_name}" />\n'
        # Insert after <manifest ...>
        self.xml_text = re.sub(
            r'(<manifest[^>]*>)',
            rf'\1\n{tag}',
            self.xml_text,
            count=1
        )

    def remove_ad_permissions(self) -> List[str]:
        """Strip common advertising and tracking permissions."""
        ad_perms = [
            "com.google.android.gms.permission.AD_ID",
            "android.permission.ACCESS_ADSERVICES_ATTRIBUTION",
            "android.permission.ACCESS_ADSERVICES_AD_ID",
            "android.permission.ACCESS_ADSERVICES_TOPICS"
        ]
        removed = []
        for p in ad_perms:
            if self.remove_permission(p):
                removed.append(p)
        return removed

    def remove_dangerous_permissions(self) -> List[str]:
        """Strip high-risk telemetry, SMS, contacts, location, and audio eavesdropping permissions."""
        dangerous = [
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.PROCESS_OUTGOING_CALLS"
        ]
        removed = []
        for p in dangerous:
            if self.remove_permission(p):
                removed.append(p)
        return removed

    def export_all_components(self) -> None:
        """Set android:exported="true" for all activities, services, receivers, and providers (for testing/fuzzing)."""
        self.xml_text = re.sub(
            r'(<(?:activity|service|receiver|provider)\b)(?!.*android:exported)',
            r'\1 android:exported="true"',
            self.xml_text
        )

    def set_version(self, version_code: Optional[int] = None, version_name: Optional[str] = None) -> None:
        """Update versionCode and versionName."""
        if version_code is not None:
            if 'android:versionCode="' in self.xml_text:
                self.xml_text = re.sub(r'android:versionCode="[^"]*"', f'android:versionCode="{version_code}"', self.xml_text)
            else:
                self.xml_text = re.sub(r'(<manifest\b)', rf'\1 android:versionCode="{version_code}"', self.xml_text, count=1)
        if version_name is not None:
            if 'android:versionName="' in self.xml_text:
                self.xml_text = re.sub(r'android:versionName="[^"]*"', f'android:versionName="{version_name}"', self.xml_text)
            else:
                self.xml_text = re.sub(r'(<manifest\b)', rf'\1 android:versionName="{version_name}"', self.xml_text, count=1)
