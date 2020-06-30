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

import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.PublicKeyCredentialType;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;


public class CborPublicKeyCredentialDescriptorParser {
    public PublicKeyCredentialDescriptor parse(byte[] data) throws IOException {
        try {
            List<DataItem> dataItems = CborDecoder.decode(data);
            if (dataItems.size() < 1) {
                throw new IOException(
                        "Failed to parse PublicKeyCredentialDescriptor, expected 1 element!");
            }
            Map cborMap = (Map) dataItems.get(0);

            PublicKeyCredentialType publicKeyCredentialType = PublicKeyCredentialType.fromString(
                    ((UnicodeString) cborMap.get(CborConstants.TYPE)).getString());
            byte[] id = ((ByteString) cborMap.get(CborConstants.ID)).getBytes();

            return PublicKeyCredentialDescriptor.create(publicKeyCredentialType, id, null);
        } catch (ClassCastException e) {
            throw new IOException("Failed to parse PublicKeyCredentialDescriptor!", e);
        } catch (CborException e) {
            throw new IOException("Failed to parse PublicKeyCredentialDescriptor!", e);
        }
    }
}
