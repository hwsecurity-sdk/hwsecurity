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


import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;


public class Ctap2CborConstants {
    public static final UnsignedInteger CBOR_ONE = new UnsignedInteger(1);
    public static final UnsignedInteger CBOR_TWO = new UnsignedInteger(2);
    public static final UnsignedInteger CBOR_THREE = new UnsignedInteger(3);
    public static final UnsignedInteger CBOR_FOUR = new UnsignedInteger(4);
    public static final UnsignedInteger CBOR_FIVE = new UnsignedInteger(5);

    public static final UnicodeString CBOR_ID = new UnicodeString("id");
    public static final UnicodeString CBOR_NAME = new UnicodeString("name");
    public static final UnicodeString CBOR_DISPLAYNAME = new UnicodeString("displayName");
    public static final UnicodeString CBOR_ICON = new UnicodeString("icon");
}
