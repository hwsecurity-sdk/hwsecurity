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

package de.cotech.hw.piv.internal;

import androidx.annotation.RestrictTo;

import java.io.IOException;
import java.util.Arrays;

import de.cotech.hw.secrets.ByteSecret;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class PivPinFormatter {

    /**
     * According to NIST SP-800-73-4:
     * - PIN must be between 6 to 8 digits
     * - If it is less than 8 digits, it must be padded with 'FF'
     */
    public static ByteSecret format(ByteSecret pinSecret) throws IOException {
        byte[] pin = new byte[8];
        byte[] unsafePinCopy = pinSecret.unsafeGetByteCopy();
        try {
            checkPinConformity(unsafePinCopy);
            Arrays.fill(pin, (byte) 0xff);
            System.arraycopy(unsafePinCopy, 0, pin, 0, unsafePinCopy.length);
        } finally {
            Arrays.fill(unsafePinCopy, (byte) 0);
        }

        return ByteSecret.fromByteArrayTakeOwnership(pin);
    }

    private static void checkPinConformity(byte[] unsafePinCopy) throws IOException {
        if (unsafePinCopy.length > 8) {
            throw new IOException("PIN is too long! (must be 6 to 8 digits)");
        }
        if (unsafePinCopy.length < 6) {
            throw new IOException("PIN is too short! (must be 6 to 8 digits)");
        }
        for (byte digit : unsafePinCopy) {
            if (digit < '0' || digit > '9') {
                throw new IOException("PIN contains non-digit characters! (must be 6 to 8 digits)");
            }
        }
    }
}
