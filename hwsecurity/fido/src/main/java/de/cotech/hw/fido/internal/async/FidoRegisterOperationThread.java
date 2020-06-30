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

import android.os.Handler;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import de.cotech.hw.fido.FidoRegisterCallback;
import de.cotech.hw.fido.FidoRegisterRequest;
import de.cotech.hw.fido.FidoRegisterResponse;
import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.fido.internal.operations.RegisterOp;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class FidoRegisterOperationThread extends FidoOperationThread<FidoRegisterResponse> {
    private final FidoRegisterCallback callback;
    private final FidoRegisterRequest registerRequest;

    private RegisterOp registerOp;
    private byte[] challengeParam;
    private byte[] applicationParam;

    public FidoRegisterOperationThread(FidoU2fAppletConnection fidoU2fAppletConnection, Handler handler,
            FidoRegisterCallback callback, FidoRegisterRequest registerRequest, int userPresenceCheckDelayMs) {
        super(fidoU2fAppletConnection, handler, userPresenceCheckDelayMs);
        this.callback = callback;
        this.registerRequest = registerRequest;
    }

    @Override
    @WorkerThread
    void prepareOperation() {
        registerOp = RegisterOp.create(fidoU2fAppletConnection);
        challengeParam = HashUtil.sha256(registerRequest.getClientData());
        applicationParam = HashUtil.sha256(registerRequest.getAppId());

        HwTimber.d("challenge param: %s", Hex.encodeHexString(challengeParam));
        HwTimber.d("application param: %s", Hex.encodeHexString(applicationParam));
        HwTimber.d("client data: %s", registerRequest.getClientData());
    }

    @Override
    @WorkerThread
    FidoRegisterResponse performOperation() throws IOException, FidoPresenceRequiredException {
        byte[] response = registerOp.register(challengeParam, applicationParam);
        return FidoRegisterResponse.create(response, registerRequest.getClientData(), registerRequest.getCustomData());
    }

    @Override
    @UiThread
    void deliverResponse(FidoRegisterResponse response) {
        callback.onRegisterResponse(response);
    }

    @Override
    @UiThread
    void deliverIoException(IOException e) {
        callback.onIoException(e);
    }
}
