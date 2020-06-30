/*
 * Copyright (C) 2018-2020 Confidential Technologies GmbH
 *
 * You can purchase a commercial license at https://hwsecurity.dev.
 * Buying such a license is mandatory as soon as you develop commercial
 * activities involving this program without disclosing the source code
 * of your own applications.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.cotech.hw.fido2;


import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;

import android.annotation.TargetApi;
import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build.VERSION_CODES;
import android.os.Handler;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.FragmentManager;
import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.internal.json.JsonPublicKeyCredentialSerializer;
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser;
import de.cotech.hw.fido2.internal.utils.AndroidUtils;
import de.cotech.hw.fido2.ui.WebauthnDialogFragment;
import de.cotech.hw.fido2.ui.WebauthnDialogFragment.OnGetAssertionCallback;
import de.cotech.hw.fido2.ui.WebauthnDialogFragment.OnMakeCredentialCallback;
import de.cotech.hw.fido2.ui.WebauthnDialogOptions;
import de.cotech.hw.util.HwTimber;
import org.json.JSONException;

import de.cotech.hw.ui.R;

/**
 * If you are using a WebView for your login flow, you can use this WebViewWebauthnBridge
 * for extending the WebView's Javascript API with the WebAuthn APIs.
 * <p>
 * Note: Currently only compatible and tested with Android SDK >= 19 due to evaluateJavascript() calls.
 */
@TargetApi(VERSION_CODES.KITKAT)
public class WebViewWebauthnBridge {
    private static final String WEBAUTHN_BRIDGE_INTERFACE = "webauthnbridgejava";
    private static final String ASSETS_BRIDGE_JS = "webauthnbridge.js";

    private final Context context;
    private final FragmentManager fragmentManager;
    private final WebView webView;
    private final WebauthnDialogOptions.Builder optionsBuilder;

    private String currentOrigin;
    private boolean loadingNewPage;
    private JsonWebauthnOptionsParser jsonWebauthnOptionsParser =
            new JsonWebauthnOptionsParser();
    private JsonPublicKeyCredentialSerializer jsonPublicKeyCredentialSerializer =
            new JsonPublicKeyCredentialSerializer();

    @SuppressWarnings("unused") // public API
    public static WebViewWebauthnBridge createInstanceForWebView(AppCompatActivity activity, WebView webView) {
        return createInstanceForWebView(activity.getApplicationContext(), activity.getSupportFragmentManager(), webView, null);
    }

    /**
     * Same as createInstanceForWebView, but allows to set WebauthnDialogOptions.Builder.
     * <p>
     * Note: Timeout and Title will be overwritten.
     */
    @SuppressWarnings("unused") // public API
    public static WebViewWebauthnBridge createInstanceForWebView(AppCompatActivity activity, WebView webView, WebauthnDialogOptions.Builder optionsBuilder) {
        return createInstanceForWebView(activity.getApplicationContext(), activity.getSupportFragmentManager(), webView, optionsBuilder);
    }

    public static WebViewWebauthnBridge createInstanceForWebView(Context context, FragmentManager fragmentManager, WebView webView) {
        return createInstanceForWebView(context, fragmentManager, webView, null);
    }

    @SuppressWarnings("WeakerAccess") // public API
    public static WebViewWebauthnBridge createInstanceForWebView(Context context, FragmentManager fragmentManager, WebView webView, WebauthnDialogOptions.Builder optionsBuilder) {
        Context applicationContext = context.getApplicationContext();

        WebauthnDialogOptions.Builder opsBuilder = optionsBuilder != null ? optionsBuilder : WebauthnDialogOptions.builder();
        WebViewWebauthnBridge webViewWebauthnBridge = new WebViewWebauthnBridge(applicationContext, fragmentManager, webView, opsBuilder);
        webViewWebauthnBridge.addJavascriptInterfaceToWebView();

        return webViewWebauthnBridge;
    }

    private WebViewWebauthnBridge(Context context, FragmentManager fragmentManager, WebView webView, WebauthnDialogOptions.Builder optionsBuilder) {
        this.context = context;
        this.fragmentManager = fragmentManager;
        this.webView = webView;
        this.optionsBuilder = optionsBuilder;
    }

    private void addJavascriptInterfaceToWebView() {
        webView.addJavascriptInterface(new JsInterface(), WEBAUTHN_BRIDGE_INTERFACE);
    }

    @Keep
    class JsInterface {
        @Keep
        @JavascriptInterface
        public void get(String options) {
            javascriptPublicKeyCredentialGet(options);
        }

        @Keep
        @JavascriptInterface
        public void store(String credential) {
            javascriptPublicKeyCredentialStore(credential);
        }

        @Keep
        @JavascriptInterface
        public void create(String options) {
            javascriptPublicKeyCredentialCreate(options);
        }

        @Keep
        @JavascriptInterface
        public void preventSilentAccess() {
            javascriptPublicKeyCredentialPreventSilentAccess();
        }
    }

    // region delegate

    /**
     * Call this in your WebViewClient.shouldInterceptRequest(WebView view, WebResourceRequest request)
     */
    @TargetApi(VERSION_CODES.LOLLIPOP)
    @SuppressWarnings("unused")
    // parity with WebViewClient.shouldInterceptRequest(WebView view, WebResourceRequest request)
    public void delegateShouldInterceptRequest(WebView view, WebResourceRequest request) {
        HwTimber.d("shouldInterceptRequest(WebView view, WebResourceRequest request) %s", request.getUrl());
        injectOnInterceptRequest();
    }

    /**
     * Call this in your WebViewClient.shouldInterceptRequest(WebView view, String url)
     */
    @TargetApi(VERSION_CODES.KITKAT)
    @SuppressWarnings("unused")
    // parity with WebViewClient.shouldInterceptRequest(WebView view, String url)
    public void delegateShouldInterceptRequest(WebView view, String url) {
        HwTimber.d("shouldInterceptRequest(WebView view, String url): %s", url);
        injectOnInterceptRequest();
    }

    @SuppressWarnings("unused") // parity with WebViewClient.onPageStarted
    public void delegateOnPageStarted(WebView view, String url, Bitmap favicon) {
        this.currentOrigin = null;
        this.loadingNewPage = false;

        if (url == null) {
            return;
        }
        Uri uri = Uri.parse(url);

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            HwTimber.e("WebAuthn only supported for HTTPS websites!");
            return;
        }

        this.currentOrigin = "https://" + uri.getAuthority();
        this.loadingNewPage = true;
    }

    private void injectOnInterceptRequest() {
        if (loadingNewPage) {
            loadingNewPage = false;
            HwTimber.d("Scheduling WebAuthn bridge injection!");
            Handler handler = new Handler(context.getMainLooper());
            handler.postAtFrontOfQueue(this::injectJavascriptBridge);
        }
    }

    private void injectJavascriptBridge() {
        try {
            String jsContent = AndroidUtils.loadTextFromAssets(context, ASSETS_BRIDGE_JS, Charset.defaultCharset());
            webView.evaluateJavascript("javascript:(" + jsContent + ")()", null);
        } catch (IOException e) {
            HwTimber.e(e);
            throw new IllegalStateException();
        }
    }

    // endregion

    private void javascriptPublicKeyCredentialGet(String optionsJsonString) {
        HwTimber.d("javascriptPublicKeyCredentialGet: %s", optionsJsonString);
        try {
            PublicKeyCredentialRequestOptions options = jsonWebauthnOptionsParser.fromOptionsJsonGetAssertion(optionsJsonString);
            javascriptPublicKeyCredentialGet(options);
        } catch (JSONException e) {
            HwTimber.e(e);
        }
    }

    private void javascriptPublicKeyCredentialGet(PublicKeyCredentialRequestOptions options) {
        PublicKeyCredentialGet
                credentialGetCommand = PublicKeyCredentialGet.create(currentOrigin, options);

        OnGetAssertionCallback onGetCredentialCallback = new OnGetAssertionCallback() {
            @Override
            public void onGetAssertionResponse(@NonNull PublicKeyCredential publicKeyCredential) {
                callJavascriptResolve(publicKeyCredential);
                HwTimber.d("response: %s", publicKeyCredential);
            }

            @Override
            public void onGetAssertionCancel() {
                HwTimber.d("operation cancelled.");
                callJavascriptCancel();
            }

            @Override
            public void onGetAssertionTimeout() {
                HwTimber.d("timeout: %s", options);
                callJavascriptTimeout();
            }
        };

        optionsBuilder.setTimeoutMs(options.timeout());
        optionsBuilder.setTitle(context.getString(R.string.hwsecurity_fido_title_default_authenticate_app_id, getDisplayOrigin(currentOrigin)));

        WebauthnDialogFragment webauthnDialogFragment = WebauthnDialogFragment.newInstance(
                credentialGetCommand, optionsBuilder.build());
        webauthnDialogFragment.setOnGetAssertionCallback(onGetCredentialCallback);
        webauthnDialogFragment.show(fragmentManager);
    }

    private void javascriptPublicKeyCredentialStore(String optionsJsonString) {
        HwTimber.e("store: Not implemented");
    }

    private void javascriptPublicKeyCredentialCreate(String optionsJsonString) {
        HwTimber.d("javascriptPublicKeyCredentialCreate: %s", optionsJsonString);
        try {
            PublicKeyCredentialCreationOptions options = jsonWebauthnOptionsParser.fromOptionsJsonMakeCredential(optionsJsonString);
            javascriptPublicKeyCredentialCreate(options);
        } catch (JSONException e) {
            HwTimber.e(e);
        }
    }

    private void javascriptPublicKeyCredentialCreate(PublicKeyCredentialCreationOptions options) {
        PublicKeyCredentialCreate
                credentialCreateCommand = PublicKeyCredentialCreate.create(currentOrigin, options);

        OnMakeCredentialCallback onMakeCredentialCallback = new OnMakeCredentialCallback() {
            @Override
            public void onMakeCredentialResponse(@NonNull PublicKeyCredential publicKeyCredential) {
                callJavascriptResolve(publicKeyCredential);
                HwTimber.d("response: %s", publicKeyCredential);
            }

            @Override
            public void onMakeCredentialCancel() {
                HwTimber.d("operation cancelled.");
                callJavascriptCancel();
            }

            @Override
            public void onMakeCredentialTimeout() {
                HwTimber.d("timeout: %s", options);
                callJavascriptTimeout();
            }
        };

        optionsBuilder.setTimeoutMs(options.timeout());
        optionsBuilder.setTitle(context.getString(R.string.hwsecurity_fido_title_default_register_app_id, getDisplayOrigin(currentOrigin)));

        WebauthnDialogFragment webauthnDialogFragment = WebauthnDialogFragment.newInstance(
                credentialCreateCommand, optionsBuilder.build());
        webauthnDialogFragment.setOnMakeCredentialCallback(onMakeCredentialCallback);
        webauthnDialogFragment.show(fragmentManager);
    }

    private void javascriptPublicKeyCredentialPreventSilentAccess() {
        HwTimber.e("preventSilentAccess: Not implemented");
    }

    private void callJavascriptCancel() {
        String javascript = "javascript:webauthnbridge.handleReject(new Error('User cancelled operation.'))";
        webView.evaluateJavascript(javascript, null);
    }

    private void callJavascriptTimeout() {
        String javascript = "javascript:webauthnbridge.handleReject(new Error('Operation timed out.'))";
        webView.evaluateJavascript(javascript, null);
    }

    private void callJavascriptResolve(PublicKeyCredential publicKeyCredential) {
        String publicKeyCredentialJson =
                jsonPublicKeyCredentialSerializer.publicKeyCredentialToJsonString(publicKeyCredential);
        String javascript = "javascript:webauthnbridge.handleResolve(" + publicKeyCredentialJson + ")";
        webView.evaluateJavascript(javascript, null);
    }

    public void setForceU2f(boolean forceU2f) {
        optionsBuilder.setForceU2f(forceU2f);
    }

    private String getDisplayOrigin(String origin) {
        try {
            URI appIdUri = new URI(origin);
            return appIdUri.getHost();
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid URI used for origin");
        }
    }
}
