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

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.AnyThread;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.LifecycleOwner;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.async.Ctap2Fido2OperationThread;
import de.cotech.hw.fido2.internal.async.Fido2AsyncOperationManager;
import de.cotech.hw.fido2.internal.async.WebauthnFido2OperationThread;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;
import de.cotech.hw.fido2.internal.json.JsonPublicKeyCredentialSerializer;
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperationFactory;
import de.cotech.hw.fido2.internal.webauthn.WebauthnCommand;
import de.cotech.hw.fido2.internal.webauthn.WebauthnResponse;
import de.cotech.hw.internal.transport.Transport;
import org.json.JSONException;


@SuppressWarnings({ "unused", "WeakerAccess" }) // All methods are public API
public class Fido2SecurityKey extends SecurityKey {
    private static final int USER_PRESENCE_CHECK_DELAY_MS = 250;

    private final Fido2AppletConnection fido2AppletConnection;
    private final Fido2AsyncOperationManager fido2AsyncOperationManager;
    private final WebauthnSecurityKeyOperationFactory operationFactory;
    private final JsonWebauthnOptionsParser jsonOptionsParser = new JsonWebauthnOptionsParser();
    private final JsonPublicKeyCredentialSerializer jsonPublicKeyCredentialSerializer =
            new JsonPublicKeyCredentialSerializer();

    Fido2SecurityKey(SecurityKeyManagerConfig config, Fido2AppletConnection fido2AppletConnection,
            Transport transport, Fido2AsyncOperationManager fido2AsyncOperationManager,
            WebauthnSecurityKeyOperationFactory operationFactory) {
        super(config, transport);
        this.fido2AppletConnection = fido2AppletConnection;
        this.fido2AsyncOperationManager = fido2AsyncOperationManager;
        this.operationFactory = operationFactory;
    }

    @WorkerThread
    String webauthnPublicKeyCredentialGet(String jsonOptions, String origin) throws IOException {
        PublicKeyCredentialRequestOptions options;
        try {
            options = jsonOptionsParser.fromOptionsJsonGetAssertion(jsonOptions);
        } catch (JSONException e) {
            throw new IOException("Invalid input parameters!", e);
        }
        PublicKeyCredentialGet request = PublicKeyCredentialGet.create(origin, options);
        PublicKeyCredential publicKeyCredential = webauthnCommand(request);
        return jsonPublicKeyCredentialSerializer.publicKeyCredentialToJsonString(publicKeyCredential);
    }

    void webauthnPublicKeyCredentialGetAsync(String jsonOptions, String origin,
            WebauthnJsonCallback callback, LifecycleOwner lifecycleOwner) throws IOException {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        webauthnPublicKeyCredentialGetAsync(jsonOptions, origin, callback, mainThreadHandler, lifecycleOwner);
    }

    void webauthnPublicKeyCredentialGetAsync(String jsonOptions, String origin,
            WebauthnJsonCallback callback, Handler handler, LifecycleOwner lifecycleOwner) throws IOException {
        PublicKeyCredentialRequestOptions options;
        try {
            options = jsonOptionsParser.fromOptionsJsonGetAssertion(jsonOptions);
        } catch (JSONException e) {
            throw new IOException("Invalid input parameters!", e);
        }
        PublicKeyCredentialGet request = PublicKeyCredentialGet.create(origin, options);
        webauthnCommandAsync(request, webauthnResponseToJsonCallback(callback), handler, lifecycleOwner);
    }

    @WorkerThread
    public String webauthnPublicKeyCredentialCreate(String jsonOptions, String origin) throws IOException {
        PublicKeyCredentialCreationOptions options;
        try {
            options = jsonOptionsParser.fromOptionsJsonMakeCredential(jsonOptions);
        } catch (JSONException e) {
            throw new IOException("Invalid input parameters!", e);
        }
        PublicKeyCredentialCreate create = PublicKeyCredentialCreate.create(origin, options);
        PublicKeyCredential publicKeyCredential = webauthnCommand(create);
        return jsonPublicKeyCredentialSerializer.publicKeyCredentialToJsonString(publicKeyCredential);
    }

    @AnyThread
    void webauthnPublicKeyCredentialCreateAsync(String jsonOptions, String origin,
            WebauthnJsonCallback callback, LifecycleOwner lifecycleOwner)
            throws IOException {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        webauthnPublicKeyCredentialCreateAsync(jsonOptions, origin, callback, mainThreadHandler, lifecycleOwner);
    }

    @AnyThread
    void webauthnPublicKeyCredentialCreateAsync(String jsonOptions, String origin,
            WebauthnJsonCallback callback, Handler handler, LifecycleOwner lifecycleOwner)
            throws IOException {
        PublicKeyCredentialCreationOptions options;
        try {
            options = jsonOptionsParser.fromOptionsJsonMakeCredential(jsonOptions);
        } catch (JSONException e) {
            throw new IOException("Invalid input parameters!", e);
        }
        PublicKeyCredentialCreate create = PublicKeyCredentialCreate.create(origin, options);
        webauthnCommandAsync(create, webauthnResponseToJsonCallback(callback), handler, lifecycleOwner);
    }

    @WorkerThread
    public <WR extends WebauthnResponse, WC extends WebauthnCommand>
    WR webauthnCommand(WC command) throws IOException {
        WebauthnSecurityKeyOperation<WR, WC> operation = operationFactory.getOperation(
                command, fido2AppletConnection.isCtap2Capable());
        return operation.performWebauthnSecurityKeyOperation(fido2AppletConnection, command);
    }

    @AnyThread
    public <T extends WebauthnResponse>
    void webauthnCommandAsync(WebauthnCommand command, WebauthnCallback<T> callback,
            LifecycleOwner lifecycleOwner) {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        webauthnCommandAsync(command, callback, mainThreadHandler, lifecycleOwner);
    }

    @AnyThread
    public <WR extends WebauthnResponse, WC extends WebauthnCommand>
    void webauthnCommandAsync(
            WC command, WebauthnCallback<WR> callback, Handler handler,
            LifecycleOwner lifecycleOwner) {
        WebauthnFido2OperationThread<WR, WC>
                fidoOperationThread = new WebauthnFido2OperationThread<>(
                fido2AppletConnection, operationFactory, handler, callback, command, USER_PRESENCE_CHECK_DELAY_MS);
        fido2AsyncOperationManager.startAsyncOperation(lifecycleOwner, fidoOperationThread);
    }

    @WorkerThread
    public <CR extends Ctap2Response> CR ctap2RawCommand(Ctap2Command<CR> ctap2Command)
            throws IOException {
        return fido2AppletConnection.ctap2CommunicateOrThrow(ctap2Command);
    }

    @AnyThread
    public <CR extends Ctap2Response> void ctap2RawCommandAsync(Ctap2Command<CR> command,
            Ctap2Callback<CR> callback, LifecycleOwner lifecycleOwner) {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        ctap2RawCommandAsync(command, callback, mainThreadHandler, lifecycleOwner);
    }

    @AnyThread
    public <CR extends Ctap2Response> void ctap2RawCommandAsync(Ctap2Command<CR> command,
            Ctap2Callback<CR> callback, Handler handler, LifecycleOwner lifecycleOwner) {
        Ctap2Fido2OperationThread<CR> ctap2Fido2OperationThread = new Ctap2Fido2OperationThread<>(
                fido2AppletConnection, handler, command, callback, USER_PRESENCE_CHECK_DELAY_MS);
        fido2AsyncOperationManager.startAsyncOperation(lifecycleOwner, ctap2Fido2OperationThread);
    }

    @AnyThread
    public void clearAsyncOperation() {
        fido2AsyncOperationManager.clearAsyncOperation();
    }

    private WebauthnCallback<PublicKeyCredential> webauthnResponseToJsonCallback(
            WebauthnJsonCallback callback) {
        return new WebauthnCallback<PublicKeyCredential>() {
            @Override
            public void onResponse(PublicKeyCredential jsonResponse) {
                jsonPublicKeyCredentialSerializer.publicKeyCredentialToJsonString(jsonResponse);
            }

            @Override
            public void onIoException(IOException e) {
                callback.onIoException(e);
            }
        };
    }
}
