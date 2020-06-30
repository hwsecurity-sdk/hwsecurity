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

package de.cotech.hw.openpgp.internal.operations;


import java.io.IOException;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.OpenPgpCapabilities;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;


@RestrictTo(Scope.LIBRARY_GROUP)
public class InternalAuthenticateOp {
    private final OpenPgpAppletConnection connection;
    private final OpenPgpSignatureUtils signatureUtils = OpenPgpSignatureUtils.getInstance();

    public static InternalAuthenticateOp create(OpenPgpAppletConnection keyInteractor) {
        return new InternalAuthenticateOp(keyInteractor);
    }

    private InternalAuthenticateOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    /**
     * Call INTERNAL AUTHENTICATE command and returns the MPI value
     *
     * @param challenge the hash for signing
     * @return a big integer representing the MPI for the given hash
     */
    public byte[] calculateAuthenticationSignature(ByteSecret pin, byte[] challenge, String hashAlgo) throws IOException {
        connection.verifyPinForOther(pin);

        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat authKeyFormat = openPgpCapabilities.getAuthKeyFormat();

        byte[] data = signatureUtils.prepareData(challenge, hashAlgo, authKeyFormat);

        // Command APDU for INTERNAL AUTHENTICATE (page 55)
        CommandApdu command = connection.getCommandFactory().createInternalAuthCommand(data);
        ResponseApdu response = connection.communicateOrThrow(command);

        return signatureUtils.encodeSignature(response.getData(), authKeyFormat);
    }
}
