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

package de.cotech.hw.openpgp.internal.operations;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.RSAKeyFormat;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


class OpenPgpSignatureUtils {
    private static final String RIPEMD160 = "RIPEMD160";
    private static final String SHA1 = "SHA1";
    private static final String SHA224 = "SHA224";
    private static final String SHA256 = "SHA256";
    private static final String SHA384 = "SHA384";
    private static final String SHA512 = "SHA512";


    static OpenPgpSignatureUtils getInstance() {
        return new OpenPgpSignatureUtils();
    }

    private OpenPgpSignatureUtils() { }


    private byte[] prepareDsi(byte[] hash, String hashAlgo) throws IOException {
        byte[] dsi;

        // to produce the DSI, we simply concatenate the hash bytes with the hash-specific DSI prefix
        switch (hashAlgo.replace("-", "")) {
            case SHA1:
                if (hash.length != 20) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 20!)");
                }
                dsi = Arrays.concatenate(Hex.decode(
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
                dsi = Arrays.concatenate(Hex.decode("3021300906052B2403020105000414"), hash);
                break;
            case SHA224:
                if (hash.length != 28) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 28!)");
                }
                dsi = Arrays.concatenate(Hex.decode("302D300D06096086480165030402040500041C"), hash);
                break;
            case SHA256:
                if (hash.length != 32) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 32!)");
                }
                dsi = Arrays.concatenate(Hex.decode("3031300D060960864801650304020105000420"), hash);
                break;
            case SHA384:
                if (hash.length != 48) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 48!)");
                }
                dsi = Arrays.concatenate(Hex.decode("3041300D060960864801650304020205000430"), hash);
                break;
            case SHA512:
                if (hash.length != 64) {
                    throw new IOException("Bad hash length (" + hash.length + ", expected 64!)");
                }
                dsi = Arrays.concatenate(Hex.decode("3051300D060960864801650304020305000440"), hash);
                break;
            default:
                throw new IOException(new NoSuchAlgorithmException("Unsupported hash algorithm: " + hashAlgo));
        }
        return dsi;
    }

    byte[] prepareData(byte[] hash, String hashAlgo, KeyFormat keyFormat) throws IOException {
        byte[] data;
        switch (keyFormat.keyFormatType()) {
            case RSAKeyFormatType:
                data = prepareDsi(hash, hashAlgo);
                break;
            case ECKeyFormatType:
            case EdDSAKeyFormatType:
                data = hash;
                break;
            default:
                throw new IOException("Not supported key type!");
        }
        return data;
    }

    byte[] encodeSignature(byte[] signature, KeyFormat keyFormat) throws IOException {
        switch (keyFormat.keyFormatType()) {
            case RSAKeyFormatType:
                return encodeRsaSignature(signature, (RSAKeyFormat) keyFormat);
            case ECKeyFormatType:
                return encodeEcdsaSignature(signature);
            case EdDSAKeyFormatType:
                return signature;
            default:
                throw new IllegalArgumentException();
        }
    }

    private byte[] encodeEcdsaSignature(byte[] signature) throws IOException {
        // "plain" encoding, see https://github.com/open-keychain/open-keychain/issues/2108
        if (signature.length % 2 != 0) {
            throw new IOException("Bad signature length!");
        }
        byte[] br = new byte[signature.length / 2];
        byte[] bs = new byte[signature.length / 2];
        for (int i = 0; i < br.length; ++i) {
            br[i] = signature[i];
            bs[i] = signature[br.length + i];
        }
        if (br[0] == 0x00 && (br[1] & 0x80) == 0) {
            br = Arrays.copyOfRange(br, 1, br.length);
        }
        if (bs[0] == 0x00 && (bs[1] & 0x80) == 0) {
            bs = Arrays.copyOfRange(bs, 1, bs.length);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream out = new ASN1OutputStream(baos);
        out.writeObject(new DERSequence(new ASN1Encodable[] { new ASN1Integer(br), new ASN1Integer(bs) }));
        out.flush();
        return baos.toByteArray();
    }

    private byte[] encodeRsaSignature(byte[] signature, RSAKeyFormat keyFormat) throws IOException {
        // No encoding necessary, but make sure the signature we received is actually the expected number of bytes long!
        int modulusLength = keyFormat.getModulusLength();
        if (signature.length != (modulusLength / 8)) {
            throw new IOException("Bad signature length! Expected " + (modulusLength / 8) +
                    " bytes, got " + signature.length);
        }
        return signature;
    }
}
