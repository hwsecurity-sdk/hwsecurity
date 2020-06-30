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


import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborBuilder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;

public class CborCtap1AttestationStatementUtil {
    public static byte[] toAttestionStatement(byte[] x509certificate, byte[] signature) {
        try {
            List<DataItem> dataItems = new CborBuilder()
                .addMap()
                    .put("sig", signature)
                    .putArray("x5c")
                        .add(x509certificate)
                    .end()
                .end()
                .build();
            return CborUtils.writeCborDataToBytes(dataItems);
        } catch (CborException e) {
            // this operation will always work
            throw new IllegalStateException(e);
        }
    }
}
