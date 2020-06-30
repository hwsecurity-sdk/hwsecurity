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


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.secrets.ByteSecret;

import java.io.IOException;


@RestrictTo(Scope.LIBRARY_GROUP)
public class ModifyPinOp {
    private static final int MIN_PW1_LENGTH = 4;
    private static final int MIN_PW3_LENGTH = 8;

    private final OpenPgpAppletConnection connection;

    public static ModifyPinOp create(OpenPgpAppletConnection connection) {
        return new ModifyPinOp(connection);
    }

    private ModifyPinOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    public void modifyPw1AndPw3(ByteSecret currentPw3, ByteSecret newPw1, ByteSecret newPw3) throws IOException {
        // Order is important for Gnuk, otherwise it will be set up in "admin less mode".
        // http://www.fsij.org/doc-gnuk/gnuk-passphrase-setting.html#set-up-pw1-pw3-and-reset-code
        modifyPw3Pin(currentPw3, newPw3);
        modifyPw1WithEffectivePw3(newPw3, newPw1);
    }

    public void modifyPw1Pin(ByteSecret currentPw3, ByteSecret newPw1) throws IOException {
        modifyPw1WithEffectivePw3(currentPw3, newPw1);
    }

    private void modifyPw1WithEffectivePw3(ByteSecret currentPw3, ByteSecret newPw1) throws IOException {
        connection.verifyPuk(currentPw3);

        int maxPw1Length = connection.getOpenPgpCapabilities().getPw3MaxLength();
        if (newPw1.length() < MIN_PW1_LENGTH || newPw1.length() > maxPw1Length) {
            throw new IOException("Invalid PIN length");
        }

        byte[] newPinCopy = newPw1.unsafeGetByteCopy();

        CommandApdu changePin = connection.getCommandFactory().createResetPw1Command(newPinCopy);
        connection.communicateOrThrow(changePin);

        connection.resetPwState();
    }

    /**
     * Modifies the security key's PW3. Before sending, the new PW3 will be validated for
     * conformance to the security key's requirements for key length.
     */
    private void modifyPw3Pin(ByteSecret currentPw3, ByteSecret newPw3) throws IOException {
        int maxPw3Length = connection.getOpenPgpCapabilities().getPw3MaxLength();

        if (newPw3.length() < MIN_PW3_LENGTH || newPw3.length() > maxPw3Length) {
            throw new IOException("Invalid PIN length");
        }

        byte[] currentPw3Copy = currentPw3.unsafeGetByteCopy();
        byte[] newPw3Copy = newPw3.unsafeGetByteCopy();

        CommandApdu changePin = connection.getCommandFactory().createChangePw3Command(currentPw3Copy, newPw3Copy);
        connection.communicateOrThrow(changePin);

        connection.invalidatePw3();
    }
}
