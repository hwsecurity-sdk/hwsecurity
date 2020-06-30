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
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.SecurityKeyException;


@RestrictTo(Scope.LIBRARY_GROUP)
public class ResetAndWipeOp {
    private static final String INVALID_PIN = "XXXXXXXXXXX";

    private final OpenPgpAppletConnection connection;

    public static ResetAndWipeOp create(OpenPgpAppletConnection connection) {
        return new ResetAndWipeOp(connection);
    }

    private ResetAndWipeOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    public void resetAndWipeSecurityKey() throws IOException {
        resetAndWipeSecurityKey(true);
    }

    /**
     * Resets security key, which deletes all keys and data objects.
     * This works by entering a wrong PIN and then Admin PIN 4 times respectively.
     * Afterwards, the security key is reactivated.
     */
    public void resetAndWipeSecurityKey(boolean reactivateSecurityKey) throws IOException {
        exhaustPw1Tries();
        exhaustPw3Tries();

        // secure messaging must be disabled before reactivation
        connection.clearSecureMessaging();

        // NOTE: keep the order here! First execute _both_ commands. Before checking _both_ responses
        // If a security key is in a bad state and terminate fails, it could still be reactivated with reactivate
        CommandApdu terminate = connection.getCommandFactory().createTerminateDfCommand();
        connection.communicate(terminate);

        if (!reactivateSecurityKey) {
            return;
        }

        CommandApdu reactivate = connection.getCommandFactory().createReactivateCommand();
        ResponseApdu response = connection.communicate(reactivate);
        if (!response.isSuccess()) {
            throw new SecurityKeyException("Reactivating failed!", response.getSw());
        }

        connection.resetPwState();
        connection.refreshConnectionCapabilities();
    }

    private byte[] getInvalidPw1() {
        int pw1MaxLength = connection.getOpenPgpCapabilities().getPw1MaxLength();
        if (pw1MaxLength < INVALID_PIN.length()) {
            return INVALID_PIN.substring(0, pw1MaxLength).getBytes();
        }
        return INVALID_PIN.getBytes();
    }

    private byte[] getInvalidPw3() {
        int pw3MaxLength = connection.getOpenPgpCapabilities().getPw3MaxLength();
        if (pw3MaxLength < INVALID_PIN.length()) {
            return INVALID_PIN.substring(0, pw3MaxLength).getBytes();
        }
        return INVALID_PIN.getBytes();
    }

    private void exhaustPw1Tries() throws IOException {
        CommandApdu verifyPw1ForSignatureCommand =
                connection.getCommandFactory().createVerifyPw1ForSignatureCommand(getInvalidPw1());

        int pw1TriesLeft = Math.max(3, connection.getOpenPgpCapabilities().getPw1TriesLeft());
        for (int i = 0; i < pw1TriesLeft; i++) {
            ResponseApdu response = connection.communicate(verifyPw1ForSignatureCommand);
            if (response.isSuccess()) {
                throw new SecurityKeyException("Should never happen, PIN XXXXXXXX has been accepted!", response.getSw());
            }
        }
    }

    private void exhaustPw3Tries() throws IOException {
        CommandApdu verifyPw3Command = connection.getCommandFactory().createVerifyPw3Command(getInvalidPw3());

        int pw3TriesLeft = Math.max(3, connection.getOpenPgpCapabilities().getPw3TriesLeft());
        for (int i = 0; i < pw3TriesLeft; i++) {
            ResponseApdu response = connection.communicate(verifyPw3Command);
            if (response.isSuccess()) { // Should NOT accept!
                throw new SecurityKeyException("Should never happen, PIN XXXXXXXX has been accepted!", response.getSw());
            }
        }
    }
}
