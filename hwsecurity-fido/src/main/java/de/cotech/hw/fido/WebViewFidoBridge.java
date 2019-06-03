/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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
import timber.log.Timber;


@TargetApi(VERSION_CODES.LOLLIPOP)
public class WebViewFidoBridge {
    private static final String FIDO_BRIDGE_INTERFACE = "fidobridgejava";
    private static final String ASSETS_BRIDGE_JS = "fidobridge.js";

    private final Context context;
    private final FragmentManager fragmentManager;
    private final WebView webView;

    private String currentLoadedHost;
    private boolean loadingNewPage;


    public static WebViewFidoBridge createInstanceForWebView(AppCompatActivity activity, WebView webView) {
        return createInstanceForWebView(activity.getApplicationContext(), activity.getSupportFragmentManager(), webView);
    }

    // TODO should this be public API?
    private static WebViewFidoBridge createInstanceForWebView(
            Context context, FragmentManager fragmentManager, WebView webView) {
        Context applicationContext = context.getApplicationContext();

        WebViewFidoBridge webViewFidoBridge = new WebViewFidoBridge(applicationContext, fragmentManager, webView);
        webViewFidoBridge.addJavascriptInterfaceToWebView();

        return webViewFidoBridge;
    }


    private WebViewFidoBridge(Context context, FragmentManager fragmentManager, WebView webView) {
        this.context = context;
        this.fragmentManager = fragmentManager;
        this.webView = webView;
    }

    private void addJavascriptInterfaceToWebView() {
        webView.addJavascriptInterface(new Object() {
            @JavascriptInterface
            public void register(String requestJson) {
                handleRegisterRequest(requestJson);
            }

            @JavascriptInterface
            public void sign(String requestJson) {
                handleSignRequest(requestJson);
            }
        }, FIDO_BRIDGE_INTERFACE);
    }

    // region delegate

    @SuppressWarnings("unused") // parity with WebViewClient.shouldInterceptRequest
    public void delegateShouldInterceptRequest(WebView view, WebResourceRequest request) {
        Timber.d("shouldInterceptRequest %s", request.getUrl());

        if (loadingNewPage) {
            loadingNewPage = false;
            Timber.d("Scheduling fido bridge injection!");
            Handler handler = new Handler(context.getMainLooper());
            handler.postAtFrontOfQueue(this::injectJavascriptFidoBridge);
        }
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
            Timber.e("Fido only supported for HTTPS websites!");
            return;
        }

        this.currentLoadedHost = uri.getHost();
        this.loadingNewPage = true;
    }

    private void injectJavascriptFidoBridge() {
        try {
            String jsContent = AndroidUtils.loadTextFromAssets(context, ASSETS_BRIDGE_JS, Charset.defaultCharset());
            webView.evaluateJavascript("javascript:(" + jsContent + ")()", null);
        } catch (IOException e) {
            Timber.e(e);
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
            Timber.e(e);
            return;
        }
        RequestData requestData = RequestData.create(u2fRegisterRequest.type(), u2fRegisterRequest.requestId());
        String appId = u2fRegisterRequest.appId() != null ? u2fRegisterRequest.appId() : getCurrentFacetId();

        try {
            checkAppIdForFacet(appId);
            String challenge = U2fApiUtils.pickChallengeForU2fV2(u2fRegisterRequest.registerRequests());

            showRegisterFragment(requestData, appId, challenge, u2fRegisterRequest.timeoutSeconds());
        } catch (IOException e) {
            Timber.e(e);
            handleError(requestData, ErrorCode.BAD_REQUEST);
        }
    }

    private void showRegisterFragment(RequestData requestData, String appId, String challenge,
            Long timeoutSeconds) {
        FidoRegisterRequest registerRequest = FidoRegisterRequest.create(
                appId, getCurrentFacetId(), challenge, requestData);
        FidoDialogOptions fidoDialogOptions = getFidoDialogOptions(timeoutSeconds);
        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(registerRequest, fidoDialogOptions);
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
            // Google's Authenticator does not return any error code when the user closes the activity
            // but we do
            Timber.d("onRegisterCancel");
            handleError(fidoRegisterRequest.getCustomData(), ErrorCode.OTHER_ERROR);
        }

        @Override
        public void onFidoRegisterTimeout(@NonNull FidoRegisterRequest fidoRegisterRequest) {
            Timber.d("onRegisterTimeout");
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
            Timber.e(e);
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
            Timber.e(e);
            handleError(requestData, ErrorCode.BAD_REQUEST);
        }
    }

    private void showSignFragment(
            RequestData requestData, String appId, List<byte[]> keyHandles, String challenge,
            Long timeoutSeconds) {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                appId, getCurrentFacetId(), challenge, keyHandles, requestData);
        FidoDialogOptions fidoDialogOptions = getFidoDialogOptions(timeoutSeconds);
        FidoDialogFragment fidoDialogFragment = FidoDialogFragment.newInstance(authenticateRequest, fidoDialogOptions);
        fidoDialogFragment.setFidoAuthenticateCallback(fidoAuthenticateCallback);
        fidoDialogFragment.show(fragmentManager);
    }

    private OnFidoAuthenticateCallback fidoAuthenticateCallback = new OnFidoAuthenticateCallback() {
        @Override
        public void onFidoAuthenticateResponse(@NonNull FidoAuthenticateResponse authenticateResponse) {
            Timber.d("onAuthenticateResponse");
            U2fResponse u2fResponse = U2fResponse.createAuthenticateResponse(
                    authenticateResponse.<RequestData>getCustomData().getRequestId(),
                    authenticateResponse.getClientData(),
                    authenticateResponse.getKeyHandle(),
                    authenticateResponse.getBytes());
            callJavascriptCallback(u2fResponse);
        }

        @Override
        public void onFidoAuthenticateCancel(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
            // Google's Authenticator does not return any error code when the user closes the activity
            // but we do
            Timber.d("onAuthenticateCancel");
            handleError(fidoAuthenticateRequest.getCustomData(), ErrorCode.OTHER_ERROR);
        }

        @Override
        public void onFidoAuthenticateTimeout(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
            Timber.d("onAuthenticateTimeout");
            handleError(fidoAuthenticateRequest.getCustomData(), ErrorCode.TIMEOUT);
        }
    };

    // endregion

    // region helpers

    private String getCurrentFacetId() {
        return "https://" + currentLoadedHost;
    }

    private void checkAppIdForFacet(String appId) throws IOException {
        Uri appIdUri = Uri.parse(appId);
        String appIdHost = appIdUri.getHost();
        if (appIdHost == null || !currentLoadedHost.endsWith(appIdHost)) {
            throw new IOException("AppID '" + appId + "' isn't allowed for FacetID '" + getCurrentFacetId() + "'!");
        }
    }

    private FidoDialogOptions getFidoDialogOptions(Long timeoutSeconds) {
        return FidoDialogOptions.builder()
//                    .setTitle(getString(R.string.fido_authenticate, getDisplayAppId(u2fAuthenticateRequest.appId)))
                .setTimeoutSeconds(timeoutSeconds)
                .build();
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
