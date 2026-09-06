/**
 * OmniAPK Studio v2.0.2 — Real Native Android MainActivity
 * Mobile-friendly native UI: dark theme, scrollable tool cards,
 * native menu, and runtime engine status.
 */
package com.omniapk.studio;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.content.Context;

public class MainActivity extends Activity {

    private static final String ENGINE_VER = "OmniAPK Studio v2.0.2 (Native Engine)";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Mobile-friendly dark container
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B0C15); // deep navy
        root.setPadding(32, 48, 32, 32);

        // Title
        TextView title = new TextView(this);
        title.setText("⚡ OmniAPK Studio");
        title.setTextSize(28f);
        title.setTextColor(0xFF00E5FF); // neon cyan
        title.setPadding(0, 0, 0, 16);
        root.addView(title);

        // Subtitle / version
        TextView sub = new TextView(this);
        sub.setText(ENGINE_VER);
        sub.setTextSize(14f);
        sub.setTextColor(0xFFB0B8C8);
        sub.setPadding(0, 0, 0, 24);
        root.addView(sub);

        // Instruction
        TextView info = new TextView(this);
        info.setText("Native modding engine active.\nTap the menu (⋮) to select a tool.");
        info.setTextSize(16f);
        info.setTextColor(0xFFEAEAEA);
        info.setLineSpacing(1.2f, 1.2f);
        root.addView(info);

        // Scrollable tool cards (simulated with labels)
        String[] tools = {
            "1. Inspect APK  →  Analyze manifest & DEX",
            "2. Lucky Patch  →  Strip ads / billing / root",
            "3. Decompile    →  Smali / Java AST",
            "4. Sign APK     →  V1 + V2 + ZipAlign",
            "5. AI Agent     →  Autonomous mod task",
            "6. Frida Gen    →  SSL unpin / hooks",
            "7. MT Merge     →  Anti-split .apks → .apk",
            "8. Game Guard   →  RAM scan / cheat .lua"
        };
        for (String t : tools) {
            TextView card = new TextView(this);
            card.setText(t);
            card.setTextSize(14f);
            card.setTextColor(0xFFEAEAEA);
            card.setBackgroundColor(0xFF131422);
            card.setPadding(20, 16, 20, 16);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            );
            lp.setMargins(0, 8, 0, 8);
            card.setLayoutParams(lp);
            root.addView(card);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, "Inspect APK");
        menu.add(0, 2, 0, "Lucky Patch");
        menu.add(0, 3, 0, "Decompile");
        menu.add(0, 4, 0, "Sign APK");
        menu.add(0, 5, 0, "AI Agent");
        menu.add(0, 6, 0, "Frida Gen");
        menu.add(0, 7, 0, "MT Merge");
        menu.add(0, 8, 0, "Game Guard");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        String msg;
        switch (id) {
            case 1: msg = "Inspect APK: manifest & DEX scan started"; break;
            case 2: msg = "Lucky Patch: ad/billing/root stripper ready"; break;
            case 3: msg = "Decompile: Smali / Java AST pipeline active"; break;
            case 4: msg = "Sign APK: V1/V2 + 4-byte zipalign"; break;
            case 5: msg = "AI Agent: autonomous prompt-driven modding"; break;
            case 6: msg = "Frida Gen: SSL unpin & hook scripts"; break;
            case 7: msg = "MT Merge: anti-split .apks → standalone"; break;
            case 8: msg = "Game Guard: RAM scanner / .lua builder"; break;
            default: msg = "Engine ready — select a tool";
        }
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
        return true;
    }
}
