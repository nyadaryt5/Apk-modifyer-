package com.omniapk.studio;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        WebView view = new WebView(this);
        view.setWebViewClient(new WebViewClient());
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        view.loadUrl("file:///android_asset/index.html");
        setContentView(view);
    }
    @Override public void onBackPressed() {
        WebView view = (WebView) findViewById(android.R.id.content);
        super.onBackPressed();
    }
}
