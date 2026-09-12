package com.v2ray.ang.ui

import android.annotation.SuppressLint
import android.net.Uri
import android.net.http.SslError
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import android.webkit.JavascriptInterface
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil

class CaptchaActivity : AppCompatActivity() {

    private var isSolved = false

    class CaptchaInterface(private val onToken: (String) -> Unit) {
        @JavascriptInterface
        fun onCaptchaSuccess(token: String) {
            onToken(token)
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "VK Verification"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val webView = WebView(this)
        setContentView(webView)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            useWideViewPort = true
            loadWithOverviewMode = true
            databaseEnabled = true
            setSupportZoom(true)
        }

        webView.addJavascriptInterface(CaptchaInterface { token ->
            runOnUiThread {
                deliverToken(token)
            }
        }, "AndroidCaptcha")

        val jsHook = """
            (function() {
                if (window.__captchaHooked) return;
                window.__captchaHooked = true;

                function report(token) {
                    if (!token || typeof token !== 'string') return;
                    try {
                        if (window.AndroidCaptcha) {
                            window.AndroidCaptcha.onCaptchaSuccess(token);
                        }
                    } catch(e) {}
                }

                function checkObj(obj) {
                    if (!obj) return;
                    if (typeof obj === 'string') {
                        try {
                            checkObj(JSON.parse(obj));
                            return;
                        } catch(e) {
                            if (obj.indexOf('success_token=') !== -1) {
                                var m = obj.match(/success_token=([A-Za-z0-9_\-\.]+)/);
                                if (m && m[1]) report(m[1]);
                            }
                        }
                        return;
                    }
                    if (obj.success_token) report(obj.success_token);
                    if (obj.response && obj.response.success_token) report(obj.response.success_token);
                    if (obj.data && obj.data.success_token) report(obj.data.success_token);
                    if (obj.successToken) report(obj.successToken);
                }

                var origFetch = window.fetch;
                if (origFetch) {
                    window.fetch = function() {
                        var p = origFetch.apply(this, arguments);
                        p.then(function(r) {
                            try {
                                r.clone().text().then(checkObj);
                            } catch(e) {}
                        }).catch(function() {});
                        return p;
                    };
                }

                var origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.send = function() {
                    this.addEventListener('load', function() {
                        checkObj(this.responseText);
                    });
                    return origSend.apply(this, arguments);
                };

                window.addEventListener('message', function(event) {
                    if (event && event.data) {
                        checkObj(event.data);
                    }
                });

                document.addEventListener('submit', function(e) {
                    try {
                        var form = e.target;
                        var el = form.querySelector('input[name="success_token"]') || form.querySelector('input[name="token"]');
                        if (el && el.value) report(el.value);
                    } catch(e) {}
                }, true);

                setInterval(function() {
                    var el = document.querySelector('input[name="success_token"]') || document.querySelector('[data-success-token]');
                    if (el) {
                        var val = el.value || el.getAttribute('data-success-token');
                        if (val) report(val);
                    }
                }, 500);
            })();
        """.trimIndent()

        webView.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                checkUrlForToken(url)
                view?.evaluateJavascript(jsHook, null)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                checkUrlForToken(url)
                view?.evaluateJavascript(jsHook, null)
            }

            override fun onLoadResource(view: WebView?, url: String?) {
                super.onLoadResource(view, url)
                checkUrlForToken(url)
                view?.evaluateJavascript(jsHook, null)
            }

            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString() ?: return false
                if (checkUrlForToken(url)) {
                    return true
                }
                return false
            }

            override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                handler?.proceed()
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onCloseWindow(window: WebView?) {
                finish()
            }
        }

        val url = intent.getStringExtra("url")
        if (url.isNullOrEmpty()) {
            finish()
            return
        }
        webView.loadUrl(url)
    }

    private fun checkUrlForToken(url: String?): Boolean {
        if (url.isNullOrEmpty()) return false
        try {
            val uri = Uri.parse(url)
            val token = uri.getQueryParameter("success_token")
                ?: uri.getQueryParameter("token")
                ?: uri.fragment?.let { frag ->
                    if (frag.contains("success_token=")) {
                        Uri.parse("https://dummy/?$frag").getQueryParameter("success_token")
                    } else null
                }
            if (!token.isNullOrEmpty()) {
                deliverToken(token)
                return true
            }
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Error parsing URL for token", e)
        }
        return false
    }

    private fun deliverToken(token: String) {
        if (isSolved) return
        isSolved = true
        LogUtil.i(AppConfig.TAG, "VK Captcha solved successfully! Delivering token to Go core")
        try {
            libv2ray.Libv2ray.submitCaptchaToken(token)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to submit captcha token to core", e)
        }
        Toast.makeText(applicationContext, "VK Verification passed! Connecting...", Toast.LENGTH_SHORT).show()
        Handler(Looper.getMainLooper()).postDelayed({ finish() }, 600)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }
}
