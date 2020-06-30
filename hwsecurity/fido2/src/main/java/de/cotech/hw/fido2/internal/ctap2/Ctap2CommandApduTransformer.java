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

package de.cotech.hw.fido2.internal.ctap2;


import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.util.Arrays;


public class Ctap2CommandApduTransformer {
    private static final int FIDO2_CLA_PROPRIETARY = 0x80;
    private static final int FIDO2_INS = 0x10;
    private static final int FIDO2_P1 = 0x00;
    private static final int FIDO2_P2 = 0x00;

    private final Ctap2CborSerializer ctap2CborSerializer = new Ctap2CborSerializer();

    public CommandApdu toCommandApdu(Ctap2Command command) {
        byte[] commandBytes = transformCommandToBytes(command);
        return transformCommandBytesToCommandApdu(commandBytes);
    }

    private CommandApdu transformCommandBytesToCommandApdu(byte[] commandBytes) {
        return CommandApdu.create(FIDO2_CLA_PROPRIETARY, FIDO2_INS, FIDO2_P1, FIDO2_P2, commandBytes);
    }

    private byte[] transformCommandToBytes(Ctap2Command command) {
        byte[] cborBytes = ctap2CborSerializer.toCborBytes(command);
        return Arrays.prepend(cborBytes, command.commandValue());
    }
}
