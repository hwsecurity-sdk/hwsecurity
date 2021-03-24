/*
 * Copyright (C) 2018-2021 Confidential Technologies GmbH
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


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECCurve;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Date;

import de.cotech.hw.util.Hwsecurity25519PublicKey;


/**
 * Fingerprints are very specific to the OpenPGP package format in RFC4880. They are not specified
 * in the OpenPGP Card Specification.
 * <p>
 * We need to calculate them correctly as they are written in the key attributes
 * and other implementations may check that they match with the retrieved public key.
 * <p>
 * We don't want to depend on the Bouncy Castle OpenPGP artifact, so we are recreating
 * the package format on demand here.
 * <p>
 * For ECDH public keys we assume the KDF parameters SHA256 and AES128.
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class Rfc4880FingerprintCalculator {

    /**
     * Calculates OpenPGP v4 fingerprint for RSA
     */
    public static byte[] calculateRsaFingerprint(RSAPublicKey publicKey, Date timestamp) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeVersionTimeAlgorithm(out, timestamp, PublicKeyAlgorithmTags.RSA_GENERAL);
            writeRsaAlgorithmSpecificPart(out, publicKey);
            byte[] encodedOpenPgpKeyBytes = out.toByteArray();

            return calculateFingerprintOrThrow(encodedOpenPgpKeyBytes);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Calculates OpenPGP v4 fingerprint for ECC
     */
    public static byte[] calculateEccFingerprint(PublicKey publicKey, EcKeyFormat ecKeyFormat, Date timestamp) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeVersionTimeAlgorithm(out, timestamp, ecKeyFormat.algorithmId());
            writeEccAlgorithmSpecificPart(out, publicKey, ecKeyFormat);
            byte[] encodedOpenPgpKeyBytes = out.toByteArray();

            return calculateFingerprintOrThrow(encodedOpenPgpKeyBytes);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static void writeVersionTimeAlgorithm(ByteArrayOutputStream out, Date timestamp, int algorithmId) {
        // b) version number = 4 (1 octet);
        // c) timestamp of key creation (4 octets);
        // d) algorithm (1 octet): 17 = DSA (example);
        out.write((byte) 4);
        long time = timestamp.getTime() / 1000;
        out.write((byte) (time >> 24));
        out.write((byte) (time >> 16));
        out.write((byte) (time >> 8));
        out.write((byte) time);
        out.write(algorithmId);
    }

    private static void writeEccAlgorithmSpecificPart(ByteArrayOutputStream out, PublicKey publicKey, EcKeyFormat ecKeyFormat)
            throws IOException {
        // e) Algorithm-specific fields.

        switch (ecKeyFormat.algorithmId()) {
            case PublicKeyAlgorithmTags.ECDH:
                // *  a variable-length field containing a curve OID, formatted as
                //      follows:
                //
                //      -  a one-octet size of the following field; values 0 and 0xFF are
                //         reserved for future extensions,
                //
                //      -  the octets representing a curve OID, defined in Section 9.2;
                //
                //   *  a MPI of an EC point representing a public key;
                //
                //   *  a variable-length field containing KDF parameters, formatted as
                //      follows:
                //
                //      -  a one-octet size of the following fields; values 0 and 0xff are
                //         reserved for future extensions;
                //
                //      -  a one-octet value 1, reserved for future extensions;
                //
                //      -  a one-octet hash function ID used with a KDF;
                //
                //      -  a one-octet algorithm ID for the symmetric algorithm used to
                //         wrap the symmetric key used for the message encryption; see
                //         Section 13.5 for details.
                //
                //   Observe that an ECDH public key is composed of the same sequence of
                //   fields that define an ECDSA key, plus the KDF parameters field.
                if (ecKeyFormat.isX25519()) {
                    Hwsecurity25519PublicKey x25519PublicKey = (Hwsecurity25519PublicKey) publicKey;
                    out.write(encodeOid(ecKeyFormat.curveOid()));
                    out.write(encodeBigIntegerAsMpi(encodeCustomCompressedPoint(x25519PublicKey.getEncoded())));
                } else {
                    ECPublicKey ecdhPublicKey = (ECPublicKey) publicKey;
                    out.write(encodeOid(ecKeyFormat.curveOid()));
                    out.write(encodeBigIntegerAsMpi(encodeUncompressedPoint(ecdhPublicKey)));
                }
                out.write(encodeKdf());
                break;
            case PublicKeyAlgorithmTags.ECDSA:
                ECPublicKey ecdsaPublicKey = (ECPublicKey) publicKey;
                // *  a variable-length field containing a curve OID, formatted as
                //      follows:
                //
                //      -  a one-octet size of the following field; values 0 and 0xFF are
                //         reserved for future extensions,
                //
                //      -  the octets representing a curve OID, defined in Section 9.2;
                //
                //   *  a MPI of an EC point representing a public key.
                out.write(encodeOid(ecKeyFormat.curveOid()));
                out.write(encodeBigIntegerAsMpi(encodeUncompressedPoint(ecdsaPublicKey)));
                break;
            case PublicKeyAlgorithmTags.EDDSA:
                Hwsecurity25519PublicKey ed25519PublicKey = (Hwsecurity25519PublicKey) publicKey;
                // *  a variable-length field containing a curve OID, formatted as
                //      follows:
                //
                //      -  a one-octet size of the following field; values 0 and 0xFF are
                //         reserved for future extensions,
                //
                //      -  the octets representing a curve OID, defined in Section 9.2;
                //
                //   *  a MPI of an EC point representing a public key Q as described
                //      under EdDSA Point Format below.
                out.write(encodeOid(ecKeyFormat.curveOid()));
                out.write(encodeBigIntegerAsMpi(encodeCustomCompressedPoint(ed25519PublicKey.getEncoded())));
                break;
            default:
                throw new IllegalStateException("Unsupported algorithm id");
        }
    }

    // see RFC4880 13.2.  ECDSA and ECDH Conversion Primitives
    private static BigInteger encodeCustomCompressedPoint(byte[] rawPoint) {
        byte[] pointEnc = new byte[1 + rawPoint.length];
        pointEnc[0] = 0x40;
        System.arraycopy(rawPoint, 0, pointEnc, 1, pointEnc.length - 1);
        return new BigInteger(1, pointEnc);
    }

    // see RFC4880 13.2.  ECDSA and ECDH Conversion Primitives
    private static BigInteger encodeUncompressedPoint(ECPublicKey publicKey) {
        ECPoint point = publicKey.getW();

        // TODO: can we get rid of the bouncy castle conversions here?
        ECCurve bcCurve = EC5Util.convertCurve(publicKey.getParams().getCurve());
        org.bouncycastle.math.ec.ECPoint bcPoint = EC5Util.convertPoint(bcCurve, point);
        org.bouncycastle.math.ec.ECPoint bcNormed = bcPoint.normalize();
        byte[] x = bcNormed.getXCoord().getEncoded();
        byte[] y = bcNormed.getYCoord().getEncoded();

        byte[] pointEnc = new byte[1 + x.length + y.length];
        pointEnc[0] = 0x04;
        System.arraycopy(x, 0, pointEnc, 1, x.length);
        System.arraycopy(y, 0, pointEnc, 1 + x.length, y.length);
        return new BigInteger(1, pointEnc);
    }

    private static byte[] encodeOid(ASN1ObjectIdentifier oid) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] boid = oid.getEncoded();
        // skip the first ASN1 byte, so it only contains len | oid
        out.write(boid, 1, boid.length - 1);

        return out.toByteArray();
    }

    private static byte[] encodeKdf() throws IOException {
        // Bouncy Castle uses these as default KDF parameters
        // kdfParams = new PGPKdfParameters(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        // see org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter

        byte size = 0x03;
        byte reserved = 0x01;
        byte hashAlgorithmId = 0x08; // HashAlgorithmTags.SHA256
        byte symmetricKeyAlgorithmId = 0x07; // SymmetricKeyAlgorithmTags.AES_128

        return new byte[]{size, reserved, hashAlgorithmId, symmetricKeyAlgorithmId};
    }

    private static void writeRsaAlgorithmSpecificPart(ByteArrayOutputStream out, RSAPublicKey publicKey) throws IOException {
        // e) Algorithm-specific fields.

        // MPI of RSA public modulus n;
        // MPI of RSA public encryption exponent e.
        out.write(encodeBigIntegerAsMpi(publicKey.getModulus()));
        out.write(encodeBigIntegerAsMpi(publicKey.getPublicExponent()));
    }

    private static byte[] calculateFingerprintOrThrow(byte[] encodedOpenPgpKeyBytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA1");

        digest.update((byte) 0x99);
        digest.update((byte) (encodedOpenPgpKeyBytes.length >> 8));
        digest.update((byte) encodedOpenPgpKeyBytes.length);
        digest.update(encodedOpenPgpKeyBytes);

        return digest.digest();
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
