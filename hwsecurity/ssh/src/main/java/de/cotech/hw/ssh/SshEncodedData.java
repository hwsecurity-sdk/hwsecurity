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

package de.cotech.hw.ssh;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;


@SuppressWarnings("unused") // include unused methods for completeness
public class SshEncodedData {
    private ByteArrayOutputStream encodedData;

    SshEncodedData() {
        this(64);
    }

    private SshEncodedData(int initialLength) {
        encodedData = new ByteArrayOutputStream(initialLength);
    }

    void putString(String string) {
        byte[] buffer = string.getBytes();
        putString(buffer);
    }

    void putString(byte[] buffer) {
        putUInt32(buffer.length);
        encodedData.write(buffer, 0, buffer.length);
    }

    void putMPInt(BigInteger mpInt) {
        byte[] buffer = mpInt.toByteArray();
        if ((buffer.length == 1) && (buffer[0] == 0)) {
            putUInt32(0);
        } else {
            putString(buffer);
        }
    }

    private void putUInt32(int uInt) {
        encodedData.write(uInt >> 24);
        encodedData.write(uInt >> 16);
        encodedData.write(uInt >> 8);
        encodedData.write(uInt);
    }

    public void putByte(byte octet) {
        encodedData.write(octet);
    }

    public void putBoolean(boolean flag) {
        if (flag) {
            encodedData.write(1);
        } else {
            encodedData.write(0);
        }
    }

    byte[] toByteArray() {
        return encodedData.toByteArray();
    }
}