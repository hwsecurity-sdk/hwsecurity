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
import java.util.Objects;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.AnyThread;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.LifecycleOwner;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.fido.internal.async.FidoAsyncOperationManager;
import de.cotech.hw.fido.internal.async.FidoAuthenticateOperationThread;
import de.cotech.hw.fido.internal.async.FidoRegisterOperationThread;
import de.cotech.hw.fido.internal.operations.AuthenticateOp;
import de.cotech.hw.fido.internal.operations.RegisterOp;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.util.HashUtil;


@SuppressWarnings({ "unused", "WeakerAccess" }) // All methods are public API
public class FidoSecurityKey extends SecurityKey {
    private static final int USER_PRESENCE_CHECK_DELAY_MS = 250;

    private final FidoU2fAppletConnection fidoU2fAppletConnection;
    private final FidoAsyncOperationManager fidoAsyncOperationManager;

    FidoSecurityKey(SecurityKeyManagerConfig config, FidoU2fAppletConnection fidoU2fAppletConnection,
            Transport transport, FidoAsyncOperationManager fidoAsyncOperationManager) {
        super(config, transport);
        this.fidoU2fAppletConnection = fidoU2fAppletConnection;
        this.fidoAsyncOperationManager = fidoAsyncOperationManager;
    }

    @WorkerThread
    public FidoRegisterResponse register(FidoRegisterRequest fidoRegisterRequest)
            throws IOException {
        byte[] challengeParam = HashUtil.sha256(fidoRegisterRequest.getClientData());
        byte[] applicationParam = HashUtil.sha256(fidoRegisterRequest.getAppId());

        RegisterOp registerOp = RegisterOp.create(fidoU2fAppletConnection);
        byte[] response = registerOp.register(challengeParam, applicationParam);

        return FidoRegisterResponse.create(response, fidoRegisterRequest.getClientData(), fidoRegisterRequest.getCustomData());
    }

    @UiThread
    public void registerAsync(FidoRegisterRequest registerRequest,
            FidoRegisterCallback callback, LifecycleOwner lifecycleOwner) {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        registerAsync(registerRequest, callback, mainThreadHandler, lifecycleOwner);
    }

    @AnyThread
    public void registerAsync(FidoRegisterRequest registerRequest,
            FidoRegisterCallback callback, Handler handler, LifecycleOwner lifecycleOwner) {
        FidoRegisterOperationThread fidoOperationThread = new FidoRegisterOperationThread(
                fidoU2fAppletConnection, handler, callback, registerRequest, USER_PRESENCE_CHECK_DELAY_MS);
        fidoAsyncOperationManager.startAsyncOperation(lifecycleOwner, fidoOperationThread);
    }

    @WorkerThread
    public FidoAuthenticateResponse authenticate(FidoAuthenticateRequest authenticateRequest)
            throws IOException {
        byte[] challengeParam = HashUtil.sha256(authenticateRequest.getClientData());
        byte[] applicationParam = HashUtil.sha256(authenticateRequest.getAppId());

        AuthenticateOp authenticateOp = AuthenticateOp.create(fidoU2fAppletConnection);

        FidoWrongKeyHandleException lastWrongKeyHandleException = null;
        for (byte[] keyHandle : authenticateRequest.getKeyHandles()) {
            try {
                byte[] response = authenticateOp.authenticate(
                        challengeParam, applicationParam, keyHandle);

                return FidoAuthenticateResponse.create(
                        authenticateRequest.getClientData(), keyHandle, response, authenticateRequest.getCustomData());
            } catch (FidoWrongKeyHandleException e) {
                lastWrongKeyHandleException = e;
            }
        }
        throw Objects.requireNonNull(lastWrongKeyHandleException);
    }

    @UiThread
    public void authenticateAsync(FidoAuthenticateRequest authenticateRequest,
            FidoAuthenticateCallback callback, LifecycleOwner lifecycleOwner) {
        Handler mainThreadHandler = new Handler(Looper.getMainLooper());
        authenticateAsync(authenticateRequest, callback, mainThreadHandler, lifecycleOwner);
    }

    @AnyThread
    public void authenticateAsync(FidoAuthenticateRequest authenticateRequest,
            FidoAuthenticateCallback callback, Handler handler, LifecycleOwner lifecycleOwner) {
        FidoAuthenticateOperationThread fidoOperationThread = new FidoAuthenticateOperationThread(
                fidoU2fAppletConnection, handler, callback, authenticateRequest, USER_PRESENCE_CHECK_DELAY_MS);
        fidoAsyncOperationManager.startAsyncOperation(lifecycleOwner, fidoOperationThread);
    }

    @AnyThread
    public void clearAsyncOperation() {
        fidoAsyncOperationManager.clearAsyncOperation();
    }
}
