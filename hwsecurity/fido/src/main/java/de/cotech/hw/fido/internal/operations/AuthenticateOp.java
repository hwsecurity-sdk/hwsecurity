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

package de.cotech.hw.fido.internal.operations;


import java.io.IOException;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;
import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;

@RestrictTo(Scope.LIBRARY_GROUP)
public class AuthenticateOp {

    private final FidoU2fAppletConnection connection;

    public static AuthenticateOp create(FidoU2fAppletConnection keyInteractor) {
        return new AuthenticateOp(keyInteractor);
    }

    private AuthenticateOp(FidoU2fAppletConnection connection) {
        this.connection = connection;
    }

    /**
     * Authentication Request
     * https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
     *
     * @param challengeParam   The challenge parameter is the SHA-256 hash of the Client Data,
     *                         a stringified JSON data structure that the FIDO Client prepares.
     *                         Among other things, the Client Data contains the challenge from
     *                         the relying party (hence the name of the parameter).
     * @param applicationParam The application parameter is the SHA-256 hash of the UTF-8 encoding
     *                         of the application identity of the application requesting the
     *                         authentication as provided by the relying party.
     * @param keyHandle        The key handle. This is provided by the relying party,
     *                         and was obtained by the relying party during registration.
     * @return
     * @throws FidoPresenceRequiredException
     * @throws FidoWrongKeyHandleException
     * @throws IOException
     */
    @WorkerThread
    public byte[] authenticate(byte[] challengeParam, byte[] applicationParam, byte[] keyHandle)
            throws IOException, FidoPresenceRequiredException, FidoWrongKeyHandleException {
        if (challengeParam.length != 32) {
            throw new IllegalArgumentException("challenge parameter must be 32 bytes long!");
        }
        if (applicationParam.length != 32) {
            throw new IllegalArgumentException("application parameter must be 32 bytes long!");
        }

        byte[] data = prepareData(challengeParam, applicationParam, keyHandle);
        CommandApdu command = connection.getCommandFactory().createAuthenticationCommand(data);
        ResponseApdu response = connection.communicateOrThrow(command);

        return response.getData();
    }

    /**
     * Prepare data send to the security key according to specification:
     * The challenge parameter [32 bytes]
     * The application parameter [32 bytes]
     * A key handle length byte [1 byte], The value is unsigned (range 0-255)
     * A key handle [length specified in previous field]
     */
    private byte[] prepareData(byte[] challengeParam, byte[] applicationParam, byte[] keyHandle) {
        byte[] data = new byte[32 + 32 + 1 + keyHandle.length];

        System.arraycopy(challengeParam, 0, data, 0, 32);
        System.arraycopy(applicationParam, 0, data, 32, 32);
        data[32 + 32] = (byte) keyHandle.length;
        System.arraycopy(keyHandle, 0, data, 32 + 32 + 1, keyHandle.length);

        return data;
    }

}
