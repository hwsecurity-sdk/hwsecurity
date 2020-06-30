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

package de.cotech.hw.fido2.internal.utils;


import java.io.IOException;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;


public class DerUtils {
    private static final byte LOWER_7_BITS = (byte) 0x7F;
    private static final int MAX_NUMBER_OF_BYTES = 4;

    public static int findDerEncodedLength(ByteBuffer buf) throws IOException {
        try {
            // skip tag byte
            buf.get();

            int i = buf.get();
            if (i == -1) {
                throw new IOException("Invalid DER: length missing");
            }

            // A single byte short length
            if ((i & ~LOWER_7_BITS) == 0) {
                return i + 2;
            }

            int num = i & LOWER_7_BITS;

            if (num > MAX_NUMBER_OF_BYTES) {
                throw new IOException("Invalid DER: length field too big (" + i + ")");
            }

            byte[] bytes = new byte[num];

            buf.get(bytes);

            int lengthValue = new BigInteger(1, bytes).intValue();
            return lengthValue + 2 + num;
        } catch (BufferUnderflowException e) {
            throw new IOException("Invalid DER: length too short", e);
        }
    }
}
