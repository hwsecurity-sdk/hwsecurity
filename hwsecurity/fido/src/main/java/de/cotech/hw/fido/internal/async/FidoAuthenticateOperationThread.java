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

package de.cotech.hw.fido.internal.async;


import java.io.IOException;
import java.util.Objects;

import android.os.Handler;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.WrongRequestLengthException;
import de.cotech.hw.fido.FidoAuthenticateCallback;
import de.cotech.hw.fido.FidoAuthenticateRequest;
import de.cotech.hw.fido.FidoAuthenticateResponse;
import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.fido.internal.operations.AuthenticateOp;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class FidoAuthenticateOperationThread extends FidoOperationThread<FidoAuthenticateResponse> {
    private final FidoAuthenticateCallback callback;
    private final FidoAuthenticateRequest authenticateRequest;

    private AuthenticateOp authenticateOp;
    private byte[] challengeParam;
    private byte[] applicationParam;
    private byte[] acceptedKeyHandle;

    public FidoAuthenticateOperationThread(FidoU2fAppletConnection fidoU2fAppletConnection, Handler handler,
            FidoAuthenticateCallback callback, FidoAuthenticateRequest authenticateRequest,
            int userPresenceCheckDelayMs) {
        super(fidoU2fAppletConnection, handler, userPresenceCheckDelayMs);

        this.callback = callback;
        this.authenticateRequest = authenticateRequest;
    }

    @Override
    @WorkerThread
    void prepareOperation() {
        authenticateOp = AuthenticateOp.create(fidoU2fAppletConnection);
        challengeParam = HashUtil.sha256(authenticateRequest.getClientData());
        applicationParam = HashUtil.sha256(authenticateRequest.getAppId());

        HwTimber.d("challenge param: %s", Hex.encodeHexString(challengeParam));
        HwTimber.d("application param: %s", Hex.encodeHexString(applicationParam));
        HwTimber.d("client data: %s", authenticateRequest.getClientData());
    }

    @Override
    @WorkerThread
    FidoAuthenticateResponse performOperation() throws IOException {
        if (acceptedKeyHandle != null) {
            return attemptAuthWithKeyHandle(acceptedKeyHandle);
        }

        return attemptAuthWithAllKeyHandles();
    }

    private FidoAuthenticateResponse attemptAuthWithAllKeyHandles() throws IOException {
        SecurityKeyException lastWrongKeyHandleException = null;
        for (byte[] keyHandle : authenticateRequest.getKeyHandles()) {
            try {
                return attemptAuthWithKeyHandle(keyHandle);
            } catch (FidoPresenceRequiredException e) {
                // if we get a presence required exception, it means the key handle was accepted
                acceptedKeyHandle = keyHandle;
                throw e;
            } catch (WrongRequestLengthException e) {
                HwTimber.d("Received %s, treating as WRONG_DATA", e.getShortErrorName());
                lastWrongKeyHandleException = e;
            } catch (FidoWrongKeyHandleException e) {
                lastWrongKeyHandleException = e;
            }
        }
        throw Objects.requireNonNull(lastWrongKeyHandleException);
    }

    private FidoAuthenticateResponse attemptAuthWithKeyHandle(byte[] acceptedKeyHandle) throws IOException {
        byte[] response = authenticateOp.authenticate(challengeParam, applicationParam, acceptedKeyHandle);
        return FidoAuthenticateResponse.create(
                authenticateRequest.getClientData(), acceptedKeyHandle, response, authenticateRequest.getCustomData());
    }

    @Override
    @UiThread
    void deliverResponse(FidoAuthenticateResponse response) {
        callback.onAuthenticateResponse(response);
    }

    @Override
    @UiThread
    void deliverIoException(IOException e) {
        callback.onIoException(e);
    }
}
