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
import de.cotech.hw.fido2.Ctap2Callback;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


public class Ctap2Fido2OperationThread<CR extends Ctap2Response> extends Fido2OperationThread<CR> {
    private final Ctap2Command<CR> ctap2Command;
    private final Ctap2Callback<CR> callback;

    public Ctap2Fido2OperationThread(
            Fido2AppletConnection fido2AppletConnection, Handler handler,
            Ctap2Command<CR> ctap2Command, Ctap2Callback<CR> callback, int userPresenceCheckDelayMs) {
        super(fido2AppletConnection, handler, userPresenceCheckDelayMs);
        this.ctap2Command = ctap2Command;
        this.callback = callback;
    }

    @WorkerThread
    CR performOperation() throws IOException {
        return fido2AppletConnection.ctap2CommunicateOrThrow(ctap2Command);
    }

    @Override
    @UiThread
    void deliverResponse(CR response) {
        callback.onResponse(response);
    }

    @Override
    @UiThread
    void deliverIoException(IOException e) {
        callback.onIoException(e);
    }
}
