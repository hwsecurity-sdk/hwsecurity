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

package de.cotech.hw.piv.internal.operations;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import java.io.IOException;

import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.piv.internal.PivAppletConnection;
import de.cotech.hw.piv.internal.PivPinFormatter;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.util.Arrays;


@RestrictTo(Scope.LIBRARY_GROUP)
public class ResetRetryCounterOp {

    private final PivAppletConnection connection;

    public static ResetRetryCounterOp create(PivAppletConnection connection) {
        return new ResetRetryCounterOp(connection);
    }

    private ResetRetryCounterOp(PivAppletConnection connection) {
        this.connection = connection;
    }

    public void modifyPin(ByteSecret currentPuk, ByteSecret newPin) throws IOException {
        ByteSecret formattedCurrentPuk = PivPinFormatter.format(currentPuk);
        ByteSecret formattedNewPin = PivPinFormatter.format(newPin);

        byte[] unsafePuk = formattedCurrentPuk.unsafeGetByteCopy();
        byte[] unsafePin = formattedNewPin.unsafeGetByteCopy();
        byte[] data = Arrays.concatenate(unsafePuk, unsafePin);

        CommandApdu changePin = connection.getCommandFactory().createResetRetryCounter(data);

        Arrays.fill(unsafePuk, (byte) 0);
        Arrays.fill(unsafePin, (byte) 0);

        connection.communicateOrThrow(changePin);

        connection.resetPwState();
    }

}
