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


import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborBuilder;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.domain.create.AttestationObject;


public class CborAttestationObjectSerializer {
    public byte[] serializeAttestationObject(AttestationObject attestationObject) throws IOException {
        try {
            return serializeAttestationObjectOrThrow(attestationObject);
        } catch (CborException e) {
            throw new IOException(e);
        }
    }

    private byte[] serializeAttestationObjectOrThrow(AttestationObject attestationObject)
            throws CborException {
        List<DataItem> cborData = new CborBuilder()
                .addMap()
                .put(CborConstants.FMT, new UnicodeString(attestationObject.fmt()))
                .put(CborConstants.AUTH_DATA, new ByteString(attestationObject.authData()))
                .put(CborConstants.ATT_STMT, CborDecoder.decode(attestationObject.attStmt()).get(0))
                .end()
                .build();
        return CborUtils.writeCborDataToBytes(cborData);
    }
}
