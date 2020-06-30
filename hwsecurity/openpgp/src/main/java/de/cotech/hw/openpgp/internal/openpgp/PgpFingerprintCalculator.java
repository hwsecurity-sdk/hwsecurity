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

package de.cotech.hw.openpgp.internal.openpgp;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;


@RestrictTo(Scope.LIBRARY_GROUP)
public class PgpFingerprintCalculator {
    public static byte[] calculateRsaFingerprint(RSAPublicKey publicKey, Date timestamp) {
        try {
            byte[] encodedOpenPgpKeyBytes = encodeRsaAlgorithmSpecificPart(publicKey, timestamp);
            return calculateFingerprintOrThrow(encodedOpenPgpKeyBytes);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] calculateEccFingerprint(ECPublicKey ecPublicKey, ASN1ObjectIdentifier curveOid, Date timestamp) {
        try {
            byte[] encodedOpenPgpKeyBytes = encodeEccAlgorithmSpecificPart(ecPublicKey, curveOid, timestamp);
            return calculateFingerprintOrThrow(encodedOpenPgpKeyBytes);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static byte[] calculateFingerprintOrThrow(byte[] encodedOpenPgpKeyBytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA1");

        digest.update((byte) 0x99);
        digest.update((byte) (encodedOpenPgpKeyBytes.length >> 8));
        digest.update((byte) encodedOpenPgpKeyBytes.length);
        digest.update(encodedOpenPgpKeyBytes);

        return digest.digest();
    }

    private static byte[] encodeEccAlgorithmSpecificPart(ECPublicKey publicKey, ASN1ObjectIdentifier curveOid, Date timestamp)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        long time = timestamp.getTime();
        out.write((byte) (time >> 24));
        out.write((byte) (time >> 16));
        out.write((byte) (time >> 8));
        out.write((byte) time);

        out.write(19); // algorithm id: rsa encrypt

        out.write(curveOid.getEncoded());
        out.write(publicKey.getEncoded()); // TODO not openpgp conform!

        return out.toByteArray();
    }

    private static byte[] encodeRsaAlgorithmSpecificPart(RSAPublicKey publicKey, Date timestamp) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        long time = timestamp.getTime();
        out.write((byte) (time >> 24));
        out.write((byte) (time >> 16));
        out.write((byte) (time >> 8));
        out.write((byte) time);

        out.write(2); // algorithm id: rsa encrypt

        out.write(encodeBigIntegerAsMpi(publicKey.getModulus()));
        out.write(encodeBigIntegerAsMpi(publicKey.getPublicExponent()));

        return out.toByteArray();
    }

    private static byte[] encodeBigIntegerAsMpi(BigInteger value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int length = value.bitLength();

        out.write(length >> 8);
        out.write(length);

        byte[] bytes = value.toByteArray();

        if (bytes[0] == 0) {
            out.write(bytes, 1, bytes.length - 1);
        } else {
            out.write(bytes, 0, bytes.length);
        }

        return out.toByteArray();
    }
}
