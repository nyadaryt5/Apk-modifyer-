"""APK Modifyer -- one toolkit for decompiling, editing, rebuilding and signing APKs.

Combines the four tool families people normally keep separate:

``apktool``    decode/build smali + resources (drives the real Apktool jar)
``apktool-m``  the same workflow on an Android device over adb
``aee``        native in-place editing (manifest, resources, files) - no JVM
``patcher``    analysis of what a build protects and what it phones home about
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
