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

package de.cotech.hw.fido2.internal.ctap2.commands.getInfo;


import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.Array;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;
import de.cotech.hw.fido2.internal.cbor.CborUtils;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;


public class AuthenticatorGetInfoResponseFactory
        implements Ctap2ResponseFactory<AuthenticatorGetInfoResponse> {
    @Override
    public AuthenticatorGetInfoResponse createResponse(byte[] responseData) throws IOException {
        try {
            return fromAuthenticatorGetInfoBytes(responseData);
        } catch (CborException e) {
            throw new IOException(e);
        }
    }

    private AuthenticatorGetInfoResponse fromAuthenticatorGetInfoBytes(byte[] responseBytes)
            throws CborException {
        List<DataItem> dataItems = CborDecoder.decode(responseBytes);
        Map map = (Map) dataItems.get(0);

        List<String> versions = null;
        List<String> extensions = null;
        byte[] aaguid = null;
        AuthenticatorOptions options = null;
        Integer maxMsgSize = null;
        List<Integer> pinProtocols = null;

        for (DataItem key : map.getKeys()) {
            int type = ((UnsignedInteger) key).getValue().intValue();
            DataItem value = map.get(key);
            switch (type) {
                // versions
                case 0x01: {
                    // definite length array (CBOR major type 4) of UTF-8 encoded strings (CBOR major type 3).
                    versions = CborUtils.cborArrayToStringArray((Array) value);
                    break;
                }

                // extensions
                case 0x02: {
                    // definite length array (CBOR major type 4) of UTF-8 encoded strings (CBOR major type 3).
                    extensions = CborUtils.cborArrayToStringArray((Array) value);
                    break;
                }

                // aaguid
                case 0x03: {
                    // byte string (CBOR major type 2). 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthN].
                    ByteString byteString = (ByteString) value;
                    aaguid = byteString.getBytes();
                    break;
                }

                // options
                case 0x04: {
                    // Definite length map (CBOR major type 5) of key-value pairs where keys are UTF8 strings (CBOR major type 3) and values are booleans (CBOR simple value 21).
                    options = cborMapToAuthenticatorOptions((Map) value);
                    break;
                }

                // maxMsgSize
                case 0x05: {
                    // unsigned integer(CBOR major type 0). This is the maximum message size supported by the authenticator.
                    UnsignedInteger unsignedInteger = (UnsignedInteger) value;
                    maxMsgSize = unsignedInteger.getValue().intValue();
                    break;
                }

                // pinProtocols
                case 0x06: {
                    // array of unsigned integers (CBOR major type). This is the list of pinProtocols supported by the authenticator.
                    pinProtocols = CborUtils.cborArrayToIntegerArray((Array) value);
                    break;
                }
            }
        }

        if (options == null) {
            options = AuthenticatorOptions.create();
        }

        return AuthenticatorGetInfoResponse.create(versions, extensions, aaguid, options, maxMsgSize, pinProtocols);
    }

    private AuthenticatorOptions cborMapToAuthenticatorOptions(Map map) {
        // defaults are handled in AuthenticatorOptions itself
        Boolean plat = null;
        Boolean rk = null;
        Boolean clientPin = null;
        Boolean up = null;
        Boolean uv = null;

        for (DataItem key : map.getKeys()) {
            UnicodeString stringKey = (UnicodeString) key;
            boolean value = map.get(key) == SimpleValue.TRUE;
            switch (stringKey.getString()) {
                case "plat": {
                    plat = value;
                    break;
                }
                case "rk": {
                    rk = value;
                    break;
                }
                case "clientPin": {
                    clientPin = value;
                    break;
                }
                case "up": {
                    up = value;
                    break;
                }
                case "uv": {
                    uv = value;
                    break;
                }
            }
        }

        return AuthenticatorOptions.create(plat, rk, clientPin, up, uv);
    }
}
