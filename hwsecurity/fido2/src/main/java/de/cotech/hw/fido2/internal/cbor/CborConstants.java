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

package de.cotech.hw.fido2.internal.cbor;


import java.io.ByteArrayOutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;


public class CborConstants {
    public static final UnicodeString FMT = new UnicodeString("fmt");
    public static final UnicodeString AUTH_DATA = new UnicodeString("authData");
    public static final UnicodeString ATT_STMT = new UnicodeString("attStmt");

    public static final UnicodeString TYPE = new UnicodeString("type");
    public static final UnicodeString ID = new UnicodeString("id");

    public static final Map EMPTY_MAP = new Map();
    public static final byte[] EMPTY_MAP_BYTES = emptyMap();

    private CborConstants() { }

    private static byte[] emptyMap() {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            new CborEncoder(outputStream).encode(EMPTY_MAP);
            return outputStream.toByteArray();
        } catch (CborException e) {
            throw new IllegalStateException(e);
        }
    }
}
