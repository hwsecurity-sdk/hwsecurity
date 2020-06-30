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

package de.cotech.hw.internal.iso7816;


import java.io.IOException;
import java.util.Arrays;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import com.google.auto.value.AutoValue;
import de.cotech.hw.util.Hex;


/** A response APDU as defined in ISO/IEC 7816-4. */
@AutoValue
@RestrictTo(Scope.LIBRARY_GROUP)
public abstract class ResponseApdu {
    private static final int APDU_SW_SUCCESS = 0x9000;

    @SuppressWarnings("mutable")
    public abstract byte[] getData();
    public abstract int getSw1();
    public abstract int getSw2();

    public static ResponseApdu create(int sw, byte[] data) {
        int sw1 = ((sw >> 8) & 0xff);
        int sw2 = (sw & 0xff);
        return new AutoValue_ResponseApdu(data, sw1, sw2);
    }

    public static ResponseApdu fromBytes(byte[] apdu) throws IOException {
        if (apdu.length < 2) {
            throw new IOException("Response APDU must be 2 bytes or larger!");
        }
        byte[] data = Arrays.copyOfRange(apdu, 0, apdu.length - 2);
        int sw1 = apdu[apdu.length -2] & 0xff;
        int sw2 = apdu[apdu.length -1] & 0xff;
        return new AutoValue_ResponseApdu(data, sw1, sw2);
    }

    public int getSw() {
        return (getSw1() << 8) | getSw2();
    }

    public boolean isSuccess() {
        return getSw() == APDU_SW_SUCCESS;
    }

    public byte[] toBytes() {
        byte[] data = getData();
        byte[] bytes = new byte[data.length + 2];
        System.arraycopy(data, 0, bytes, 0, data.length);

        bytes[bytes.length -2] = (byte) getSw1();
        bytes[bytes.length -1] = (byte) getSw2();

        return bytes;
    }

    @Override
    final public String toString() {
        return Hex.encodeHexString(toBytes()) + " ResponseApdu{" +
                "data=" + Hex.encodeHexString(getData()) + ", " +
                "sw1=" + Integer.toHexString(getSw1()) + ", " +
                "sw2=" + Integer.toHexString(getSw2()) + "}";
    }
}
