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

package de.cotech.hw.fido2.internal.cose;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborBuilder;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor.CborUtils;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;
import de.cotech.hw.util.Arrays;


public class CosePublicKeyUtils {
    private static final int X962_UNCOMPRESSED = 0x04;

    public static byte[] encodex962PublicKeyAsCose(byte[] publicKey) throws IOException {
        if (publicKey.length != 65) {
            throw new IOException("Invalid length for X9.62 public key!");
        }
        if (publicKey[0] != X962_UNCOMPRESSED) {
            throw new IOException("X9.62 public key must be uncompressed format!");
        }
        byte[] x = Arrays.copyOfRange(publicKey, 1, 33);
        byte[] y = Arrays.copyOfRange(publicKey, 33, 65);
        List<DataItem> coseKeyCbor = new CborBuilder()
                .addMap()
                    .put(CoseIdentifiers.KTY, CoseIdentifiers.KTY_EC2)
                    .put(CoseIdentifiers.ALG, CoseAlg.ES256.cborLabel)
                    .put(CoseIdentifiers.CRV, CoseIdentifiers.CRV_P256)
                    .put(CoseIdentifiers.X, new ByteString(x))
                    .put(CoseIdentifiers.Y, new ByteString(y))
                .end()
                .build();
        try {
            return CborUtils.writeCborDataToBytes(coseKeyCbor);
        } catch (CborException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] encodeCosePublicKeyAsX962(byte[] publicKey) throws IOException {
        DataItem dataItem;
        try {
            CborDecoder decoder = new CborDecoder(new ByteArrayInputStream(publicKey));
            dataItem = decoder.decodeNext();
            if (decoder.decodeNext() != null) {
                throw new IOException("Unexpected trailing CBOR data");
            }
        } catch (CborException e) {
            throw new IOException("Error parsing CBOR data for COSE public key!", e);
        }
        if (dataItem.getMajorType() != MajorType.MAP) {
            throw new IOException("Expected map in CBOR data, found " + dataItem.getMajorType());
        }

        Map map = (Map) dataItem;
        DataItem kty = map.get(CoseIdentifiers.KTY);
        if (!CoseIdentifiers.KTY_EC2.equals(kty)) {
            throw new IOException("Unexpected kty value. Expected " + CoseIdentifiers.KTY_EC2 + ", got " + kty);
        }
        DataItem alg = map.get(CoseIdentifiers.ALG);
        if (!CoseAlg.ECDH_ES_w_HKDF_256.cborLabel.equals(alg) && !CoseAlg.ES256.cborLabel.equals(alg)) {
            throw new IOException("Unexpected alg value. Expected " + CoseAlg.ES256.cborLabel + " or " + CoseAlg.ECDH_ES_w_HKDF_256.cborLabel + ", got " + alg);
        }
        DataItem crv = map.get(CoseIdentifiers.CRV);
        if (!CoseIdentifiers.CRV_P256.equals(crv)) {
            throw new IOException("Unexpected crv value. Expected " + CoseIdentifiers.CRV_P256 + ", got " + crv);
        }

        DataItem x = map.get(CoseIdentifiers.X);
        if (x == null) {
            throw new IOException("Missing CBOR field X in COSE public key!");
        }
        if (x.getMajorType() != MajorType.BYTE_STRING) {
            throw new IOException("Expected X CBOR field to be a ByteString!");
        }
        byte[] xBytes = ((ByteString) x).getBytes();
        if (xBytes.length != 32) {
            throw new IOException("Expected X field to be 32 bytes, got " + xBytes.length + "!");
        }

        DataItem y = map.get(CoseIdentifiers.Y);
        if (y == null) {
            throw new IOException("Missing CBOR field X in COSE public key!");
        }
        if (y.getMajorType() != MajorType.BYTE_STRING) {
            throw new IOException("Expected Y CBOR field to be a ByteString!");
        }
        byte[] yBytes = ((ByteString) y).getBytes();
        if (yBytes.length != 32) {
            throw new IOException("Expected X field to be 32 bytes, got " + xBytes.length + "!");
        }

        byte[] x9PublicKey = new byte[65];
        x9PublicKey[0] = X962_UNCOMPRESSED;
        System.arraycopy(xBytes, 0, x9PublicKey, 1, 32);
        System.arraycopy(yBytes, 0, x9PublicKey, 33, 32);
        return x9PublicKey;
    }
}
