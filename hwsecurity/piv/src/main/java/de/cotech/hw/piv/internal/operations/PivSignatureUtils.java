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

package de.cotech.hw.piv.internal.operations;


import androidx.annotation.VisibleForTesting;
import de.cotech.hw.internal.iso7816.Iso7816TLV;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.Hex;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;


class PivSignatureUtils {
    private static final String RIPEMD160 = "RIPEMD160";
    private static final String SHA1 = "SHA1";
    private static final String SHA224 = "SHA224";
    private static final String SHA256 = "SHA256";
    private static final String SHA384 = "SHA384";
    private static final String SHA512 = "SHA512";

    static PivSignatureUtils getInstance() {
        return new PivSignatureUtils();
    }

    private PivSignatureUtils() { }

    byte[] prepareData(byte[] hash, PublicKey publicKey, String hashAlgo) throws IOException {
        if (publicKey instanceof RSAPublicKey) {
            int bitLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
            byte[] dsi = prepareDsi(hash, hashAlgo);
            hash = pkcs1Pad(dsi, bitLength / 8);
        }

        byte[] hashWithLength = Arrays.concatenate(Iso7816TLV.encodeLength(hash.length), hash);
        byte[] tmp1 = Arrays.concatenate(Hex.decodeHexOrFail("820081"), hashWithLength);
        byte[] tmp2 = Arrays.concatenate(Iso7816TLV.encodeLength(tmp1.length), tmp1);
        return Arrays.concatenate(Hex.decodeHexOrFail("7C"), tmp2);
    }

    private byte[] prepareDsi(byte[] hash, String hashAlgo) throws IOException {
        // digestinfo part of https://tools.ietf.org/html/rfc8017#section-9.3
        byte[] dsi;

        // to produce the DSI, we simply concatenate the hash bytes with the hash-specific DSI prefix
        switch (hashAlgo.replace("-", "")) {
            case SHA1:
                if (hash.length != 20) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 20!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail(
                        "3021" // Tag/Length of Sequence, the 0x21 includes all following 33 bytes
                                + "3009" // Tag/Length of Sequence, the 0x09 are the following header bytes
                                + "0605" + "2B0E03021A" // OID of SHA1
                                + "0500" // TLV coding of ZERO
                                + "0414"), hash); // 0x14 are 20 hash bytes
                break;
            case RIPEMD160:
                if (hash.length != 20) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 20!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail("3021300906052B2403020105000414"), hash);
                break;
            case SHA224:
                if (hash.length != 28) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 28!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail("302D300D06096086480165030402040500041C"), hash);
                break;
            case SHA256:
                if (hash.length != 32) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 32!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail("3031300D060960864801650304020105000420"), hash);
                break;
            case SHA384:
                if (hash.length != 48) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 48!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail("3041300D060960864801650304020205000430"), hash);
                break;
            case SHA512:
                if (hash.length != 64) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 64!)");
                }
                dsi = Arrays.concatenate(Hex.decodeHexOrFail("3051300D060960864801650304020305000440"), hash);
                break;
            default:
                throw new IOException(new NoSuchAlgorithmException("Unsupported hash algorithm: " + hashAlgo));
        }

        return dsi;
    }

    @VisibleForTesting
    byte[] pkcs1Pad(byte[] dsi, int blockSize) {
        // padding part of https://tools.ietf.org/html/rfc8017#section-9.3
        byte[] result = new byte[blockSize];
        result[0] = 0x00;
        result[1] = 0x01;
        for (int i = 2; i < (blockSize - dsi.length - 1); i++) {
            result[i] = (byte) 0xff;
        }
        result[blockSize - dsi.length - 1] = 0x00;
        System.arraycopy(dsi, 0, result, blockSize - dsi.length, dsi.length);
        return result;
    }

    byte[] unpackSignatureData(byte[] signature) throws IOException {
        Iso7816TLV tlv = Iso7816TLV.readSingle(signature, true);
        Iso7816TLV outer = Iso7816TLV.find(tlv, 0x7C);
        if (outer == null) {
            throw new IOException("Malformed signature TLV value (no 0x7C tag)");
        }
        Iso7816TLV inner = Iso7816TLV.find(outer, 0x82);
        if (inner == null) {
            throw new IOException("Malformed signature TLV value (no 0x82 tag)");
        }
        return inner.mV;
    }
}
