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

package de.cotech.hw.fido;


import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.List;

import android.annotation.TargetApi;
import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build.VERSION_CODES;
import android.os.Handler;
import android.os.Parcelable;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.FragmentManager;

import com.google.auto.value.AutoValue;

import de.cotech.hw.fido.internal.jsapi.U2fApiUtils;
import de.cotech.hw.fido.internal.jsapi.U2fAuthenticateRequest;
import de.cotech.hw.fido.internal.jsapi.U2fJsonParser;
import de.cotech.hw.fido.internal.jsapi.U2fJsonSerializer;
import de.cotech.hw.fido.internal.jsapi.U2fRegisterRequest;
import de.cotech.hw.fido.internal.jsapi.U2fResponse;
import de.cotech.hw.fido.internal.jsapi.U2fResponse.ErrorCode;
import de.cotech.hw.fido.internal.utils.AndroidUtils;
import de.cotech.hw.fido.ui.FidoDialogFragment;
import de.cotech.hw.fido.ui.FidoDialogFragment.OnFidoAuthenticateCallback;
import de.cotech.hw.fido.ui.FidoDialogFragment.OnFidoRegisterCallback;
import de.cotech.hw.fido.ui.FidoDialogOptions;
import de.cotech.hw.util.HwTimber;

import de.cotech.hw.ui.R;


/**
 * If you are using a WebView for your login flow, you can use this WebViewFidoBridge
 * for extending the WebView's Javascript API with the official FIDO U2F APIs.
 * <p>
 * Currently supported:
 * - High level API of U2F v1.1, https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-javascript-api-v1.2-ps-20170411.html
 * <p>
 * Note: Currently only compatible and tested with Android SDK >= 19 due to evaluateJavascript() calls.
 */
@TargetApi(VERSION_CODES.KITKAT)
public class WebViewFidoBridge {
    private static final String FIDO_BRIDGE_INTERFACE = "fidobridgejava";
    private static final String ASSETS_BRIDGE_JS = "fidobridge.js";

    private final Context context;
    private final FragmentManager fragmentManager;
    private final WebView webView;
    private final FidoDialogOptions.Builder optionsBuilder;

    private String currentLoadedHost;
    private boolean loadingNewPage;

    @SuppressWarnings("unused") // public API
    public static WebViewFidoBridge createInstanceForWebView(AppCompatActivity activity, WebView webView) {
        return createInstanceForWebView(activity.getApplicationContext(), activity.getSupportFragmentManager(), webView, null);
    }

    /**
     * Same as createInstanceForWebView, but allows to set FidoDialogOptions.
     * <p>
     * Note: Timeout and Title will be overwritten.
     */
    @SuppressWarnings("unused") // public API
    public static WebViewFidoBridge createInstanceForWebView(AppCompatActivity activity, WebView webView, FidoDialogOptions.Builder optionsBuilder) {
        return createInstanceForWebView(activity.getApplicationContext(), activity.getSupportFragmentManager(), webView, optionsBuilder);
    }

    public static WebViewFidoBridge createInstanceForWebView(Context context, FragmentManager fragmentManager, WebView webView) {
        return createInstanceForWebView(context, fragmentManager, webView, null);
    }

    @SuppressWarnings("WeakerAccess") // public API
    public static WebViewFidoBridge createInstanceForWebView(Context context, FragmentManager fragmentManager, WebView webView, FidoDialogOptions.Builder optionsBuilder) {
        Context applicationContext = context.getApplicationContext();

        WebViewFidoBridge webViewFidoBridge = new WebViewFidoBridge(applicationContext, fragmentManager, webView, optionsBuilder);
        webViewFidoBridge.addJavascriptInterfaceToWebView();

        return webViewFidoBridge;
    }

    private WebViewFidoBridge(Context context, FragmentManager fragmentManager, WebView webView, FidoDialogOptions.Builder optionsBuilder) {
        this.context = context;
        this.fragmentManager = fragmentManager;
        this.webView = webView;
        this.optionsBuilder = optionsBuilder;
    }

    private void addJavascriptInterfaceToWebView() {
        webView.addJavascriptInterface(new JsInterface(), FIDO_BRIDGE_INTERFACE);
    }

    @Keep
    class JsInterface {
        @Keep
        @JavascriptInterface
        public void register(String requestJson) {
            handleRegisterRequest(requestJson);
        }

        @Keep
        @JavascriptInterface
        public void sign(String requestJson) {
            handleSignRequest(requestJson);
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
        this.currentLoadedHost = null;
        this.loadingNewPage = false;

        if (url == null) {
            return;
        }
        Uri uri = Uri.parse(url);

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            HwTimber.e("Fido only supported for HTTPS websites!");
            return;
        }

        this.currentLoadedHost = uri.getHost();
        this.loadingNewPage = true;
    }

    private void injectOnInterceptRequest() {
        if (loadingNewPage) {
            loadingNewPage = false;
            HwTimber.d("Scheduling fido bridge injection!");
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

    // region register

    private void handleRegisterRequest(String requestJson) {
        U2fRegisterRequest u2fRegisterRequest;
        try {
            u2fRegisterRequest = U2fJsonParser.parseU2fRegisterRequest(requestJson);
        } catch (IOException e) {
            HwTimber.e(e);
            return;
        }
        RequestData requestData = RequestData.create(u2fRegisterRequest.type(), u2fRegisterRequest.requestId());
        String appId = u2fRegisterRequest.appId() != null ? u2fRegisterRequest.appId() : getCurrentFacetId();

        try {
            checkAppIdForFacet(appId);
            String challenge = U2fApiUtils.pickChallengeForU2fV2(u2fRegisterRequest.registerRequests());

            showRegisterFragment(requestData, appId, challenge, u2fRegisterRequest.timeoutSeconds());
        } catch (IOException e) {
            HwTimber.e(e);
            handleError(requestData, ErrorCode.BAD_REQUEST);
        }
    }

    private void showRegisterFragment(RequestData requestData, String appId, String challenge,
                                      Long timeoutSeconds) {
        FidoRegisterRequest registerRequest = FidoRegisterRequest.create(
                appId, getCurrentFacetId(), challenge, requestData);

        FidoDialogOptions.Builder opsBuilder = optionsBuilder != null ? optionsBuilder : FidoDialogOptions.builder();
        opsBuilder.setTimeoutSeconds(timeoutSeconds);
        opsBuilder.setTitle(context.getString(R.string.hwsecurity_fido_title_default_register_app_id, getDisplayAppId(appId)));

        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(registerRequest, opsBuilder.build());
        fidoDialogFragment.setFidoRegisterCallback(fidoRegisterCallback);
        fidoDialogFragment.show(fragmentManager);
    }

    private OnFidoRegisterCallback fidoRegisterCallback = new OnFidoRegisterCallback() {
        @Override
        public void onFidoRegisterResponse(@NonNull FidoRegisterResponse registerResponse) {
            Long requestId = registerResponse.<RequestData>getCustomData().getRequestId();
            U2fResponse u2fResponse = U2fResponse.createRegisterResponse(
                    requestId, registerResponse.getClientData(), registerResponse.getBytes());
            callJavascriptCallback(u2fResponse);
        }

        @Override
        public void onFidoRegisterCancel(@NonNull FidoRegisterRequest fidoRegisterRequest) {
            // Google's Authenticator does not return error codes when the user closes the activity, but we do
            handleError(fidoRegisterRequest.getCustomData(), ErrorCode.OTHER_ERROR);
        }

        @Override
        public void onFidoRegisterTimeout(@NonNull FidoRegisterRequest fidoRegisterRequest) {
            handleError(fidoRegisterRequest.getCustomData(), ErrorCode.TIMEOUT);
        }
    };

    // endregion

    // region sign

    private void handleSignRequest(String requestJson) {
        U2fAuthenticateRequest u2fAuthenticateRequest;
        try {
            u2fAuthenticateRequest = U2fJsonParser.parseU2fAuthenticateRequest(requestJson);
        } catch (IOException e) {
            HwTimber.e(e);
            return;
        }
        RequestData requestData = RequestData.create(u2fAuthenticateRequest.type(), u2fAuthenticateRequest.requestId());
        String appId = u2fAuthenticateRequest.appId() != null ? u2fAuthenticateRequest.appId() : getCurrentFacetId();

        try {
            checkAppIdForFacet(appId);
            List<byte[]> keyHandles = U2fApiUtils.getKeyHandles(u2fAuthenticateRequest.registeredKeys());

            showSignFragment(requestData, appId, keyHandles,
                    u2fAuthenticateRequest.challenge(), u2fAuthenticateRequest.timeoutSeconds());
        } catch (IOException e) {
            HwTimber.e(e);
            handleError(requestData, ErrorCode.BAD_REQUEST);
        }
    }

    private void showSignFragment(
            RequestData requestData, String appId, List<byte[]> keyHandles, String challenge,
            Long timeoutSeconds) {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                appId, getCurrentFacetId(), challenge, keyHandles, requestData);

        FidoDialogOptions.Builder opsBuilder = optionsBuilder != null ? optionsBuilder : FidoDialogOptions.builder();
        opsBuilder.setTimeoutSeconds(timeoutSeconds);
        opsBuilder.setTitle(context.getString(R.string.hwsecurity_fido_title_default_authenticate_app_id, getDisplayAppId(appId)));

        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(authenticateRequest, opsBuilder.build());
        fidoDialogFragment.setFidoAuthenticateCallback(fidoAuthenticateCallback);
        fidoDialogFragment.show(fragmentManager);
    }

    private OnFidoAuthenticateCallback fidoAuthenticateCallback = new OnFidoAuthenticateCallback() {
        @Override
        public void onFidoAuthenticateResponse(@NonNull FidoAuthenticateResponse authenticateResponse) {
            U2fResponse u2fResponse = U2fResponse.createAuthenticateResponse(
                    authenticateResponse.<RequestData>getCustomData().getRequestId(),
                    authenticateResponse.getClientData(),
                    authenticateResponse.getKeyHandle(),
                    authenticateResponse.getBytes());
            callJavascriptCallback(u2fResponse);
        }

        @Override
        public void onFidoAuthenticateCancel(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
            // Google's Authenticator does not return error codes when the user closes the activity, but we do
            handleError(fidoAuthenticateRequest.getCustomData(), ErrorCode.OTHER_ERROR);
        }

        @Override
        public void onFidoAuthenticateTimeout(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
            handleError(fidoAuthenticateRequest.getCustomData(), ErrorCode.TIMEOUT);
        }
    };

    // endregion

    // region helpers

    private String getCurrentFacetId() {
        return "https://" + currentLoadedHost;
    }

    private String getDisplayAppId(String appId) {
        try {
            URI appIdUri = new URI(appId);
            return appIdUri.getHost();
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Invalid URI used for appId");
        }
    }

    private void checkAppIdForFacet(String appId) throws IOException {
        Uri appIdUri = Uri.parse(appId);
        String appIdHost = appIdUri.getHost();
        if (appIdHost == null || !currentLoadedHost.endsWith(appIdHost)) {
            throw new IOException("AppID '" + appId + "' isn't allowed for FacetID '" + getCurrentFacetId() + "'!");
        }
    }

    private void handleError(RequestData requestData, ErrorCode errorCode) {
        U2fResponse u2fResponse = U2fResponse.createErrorResponse(
                requestData.getType(), requestData.getRequestId(), errorCode);
        callJavascriptCallback(u2fResponse);
    }

    private void callJavascriptCallback(U2fResponse u2fResponse) {
        String javascript = "javascript:fidobridge.responseHandler(" + U2fJsonSerializer.responseToJson(u2fResponse) + ")";
        webView.evaluateJavascript(javascript, null);
    }

    // endregion

    @AutoValue
    abstract static class RequestData implements Parcelable {
        public static RequestData create(String type, Long requestId) {
            return new AutoValue_WebViewFidoBridge_RequestData(type, requestId);
        }

        abstract String getType();

        @Nullable
        abstract Long getRequestId();
    }
}
