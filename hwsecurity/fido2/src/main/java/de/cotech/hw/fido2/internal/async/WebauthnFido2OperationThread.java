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

package de.cotech.hw.fido2.internal.async;


import java.io.IOException;

import android.os.Handler;

import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import de.cotech.hw.fido2.WebauthnCallback;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperationFactory;
import de.cotech.hw.fido2.internal.webauthn.WebauthnCommand;
import de.cotech.hw.fido2.internal.webauthn.WebauthnResponse;


public class WebauthnFido2OperationThread<WR extends WebauthnResponse, WC extends WebauthnCommand>
        extends Fido2OperationThread<WR> {
    private final WC webauthnCommand;
    private final WebauthnCallback<WR> callback;
    private final WebauthnSecurityKeyOperation<WR, WC> operation;

    public WebauthnFido2OperationThread(
            Fido2AppletConnection fido2AppletConnection,
            WebauthnSecurityKeyOperationFactory operationFactory,
            Handler handler, WebauthnCallback<WR> callback, WC webauthnCommand,
            int userPresenceCheckDelayMs
    ) {
        super(fido2AppletConnection, handler, userPresenceCheckDelayMs);
        this.callback = callback;
        this.webauthnCommand = webauthnCommand;
        this.operation = operationFactory.getOperation(webauthnCommand, fido2AppletConnection.isCtap2Capable());
    }

    @WorkerThread
    WR performOperation() throws IOException {
        return operation.performWebauthnSecurityKeyOperation(fido2AppletConnection, webauthnCommand);
    }

    @Override
    @UiThread
    void deliverResponse(WR response) {
        callback.onResponse(response);
    }

    @Override
    @UiThread
    void deliverIoException(IOException e) {
        callback.onIoException(e);
    }
}
