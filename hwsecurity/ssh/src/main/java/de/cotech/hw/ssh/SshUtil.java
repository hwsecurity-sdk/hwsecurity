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

package de.cotech.hw.ssh;


import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;


class SshUtil {
    private static final String OPENSSH_CERT_SUFFIX = "-cert-v01@openssh.com";

    @NonNull
    static String encodeKeyBlobAsKeyString(String algorithmName, byte[] sshEncodedData) {
        String keyBlob = Base64.toBase64String(sshEncodedData);
        return algorithmName + " " + keyBlob;
    }

    @NonNull
    static String stripAlgorithmCertSuffix(@NonNull String algorithmName) {
        if (algorithmName.endsWith(OPENSSH_CERT_SUFFIX)) {
            return algorithmName.substring(0, algorithmName.length() - OPENSSH_CERT_SUFFIX.length());
        }
        return algorithmName;
    }

    static byte[] encodeEcPublicKey(ASN1ObjectIdentifier oid, ECPublicKey publicKey)
            throws NoSuchAlgorithmException {
        return encodeEcPublicKey(getCurveName(oid), encodeEcQ(publicKey));
    }

    private static byte[] encodeEcPublicKey(String sshCurveIdentifier, byte[] Q) {
        SshEncodedData sshEncodedData = new SshEncodedData();
        sshEncodedData.putString("ecdsa-sha2-" + sshCurveIdentifier);
        sshEncodedData.putString(sshCurveIdentifier);
        sshEncodedData.putString(Q);
        return sshEncodedData.toByteArray();
    }

    private static byte[] encodeEcQ(ECPublicKey publicKey) {
        return encodeEcQ(publicKey.getW(), publicKey.getParams().getCurve());
    }

    /**
     * SECG 2.3.3 ECPoint to Octet String
     */
    private static byte[] encodeEcQ(ECPoint point, EllipticCurve curve) {
        int elementSize = getElementSize(curve);
        byte[] X = stripLeadingZeroes(point.getAffineX().toByteArray());
        byte[] Y = stripLeadingZeroes(point.getAffineY().toByteArray());

        byte[] Q = new byte[2 * elementSize + 1];
        Q[0] = 0x04;
        System.arraycopy(X, 0, Q, 1 + elementSize - X.length, X.length);
        System.arraycopy(Y, 0, Q, 1 + 2 * elementSize - Y.length, Y.length);
        return Q;
    }

    private static byte[] stripLeadingZeroes(byte[] bytes) {
        int start = 0;
        while (bytes[start] == 0x0) {
            start++;
        }

        return Arrays.copyOfRange(bytes, start, bytes.length);
    }

    private static int getElementSize(EllipticCurve curve) {
        int fieldSize = curve.getField().getFieldSize();
        return (fieldSize + 7) / 8;
    }

    static byte[] encodeRsaPublicKey(RSAPublicKey publicKey) {
        SshEncodedData sshEncodedData = new SshEncodedData();
        sshEncodedData.putString("ssh-rsa");
        sshEncodedData.putMPInt(publicKey.getPublicExponent());
        sshEncodedData.putMPInt(publicKey.getModulus());
        return sshEncodedData.toByteArray();
    }

    static byte[] encodeSshSignature(String sshAlgorithmName, byte[] signedChallenge)
            throws NoSuchAlgorithmException, IOException {
        if ("ssh-rsa".equals(sshAlgorithmName) || sshAlgorithmName.startsWith("rsa-")) {
            return encodeSshSignatureRsa(sshAlgorithmName, signedChallenge);
        }
        if (sshAlgorithmName.startsWith("ecdsa-sha2-")) {
            return encodeSshSignatureEcdsa(sshAlgorithmName, signedChallenge);
        }
        if ("ssh-ed25519".equals(sshAlgorithmName)) {
            return encodeSshSignatureEddsa(sshAlgorithmName, signedChallenge);
        }
        throw new NoSuchAlgorithmException("Unknown ssh algorithm name, cannot encode signature!");
    }

    private static byte[] encodeSshSignatureEddsa(String sshAlgorithmName, byte[] signedChallenge) {
        SshEncodedData result = new SshEncodedData();
        result.putString(sshAlgorithmName);
        result.putString(signedChallenge);
        return result.toByteArray();
    }

    private static byte[] encodeSshSignatureEcdsa(String sshAlgorithmName, byte[] rawSignature) throws IOException {
        byte[] signatureRsBlob = encodeSignatureAsn1RsBlob(rawSignature);

        SshEncodedData result = new SshEncodedData();
        result.putString(sshAlgorithmName);
        result.putString(signatureRsBlob);
        return result.toByteArray();
    }

    private static byte[] encodeSignatureAsn1RsBlob(byte[] rawSignature) throws IOException {
        ASN1Sequence asn1Sequence = getASN1Sequence(rawSignature);
        BigInteger r = getAsn1IntegerAtIndex(asn1Sequence, 0);
        BigInteger s = getAsn1IntegerAtIndex(asn1Sequence, 1);

        SshEncodedData rsBlob = new SshEncodedData();
        rsBlob.putMPInt(r);
        rsBlob.putMPInt(s);
        return rsBlob.toByteArray();
    }

    private static BigInteger getAsn1IntegerAtIndex(ASN1Sequence asn1Sequence, int index) throws IOException {
        try {
            return ASN1Integer.getInstance(asn1Sequence.getObjectAt(index)).getValue();
        } catch (IllegalArgumentException e) {
            throw new IOException("Could not read ASN.1 integer");
        }
    }

    private static ASN1Sequence getASN1Sequence(byte[] rawSignature) throws IOException {
        try {
            return (ASN1Sequence) ASN1Primitive.fromByteArray(rawSignature);
        } catch (IOException e) {
            throw new IOException("Could not read ASN.1 object");
        }
    }

    private static byte[] encodeSshSignatureRsa(String hashAlgorithm, byte[] rawSignature) {
        SshEncodedData signature = new SshEncodedData();
        signature.putString(hashAlgorithm);
        signature.putString(rawSignature);
        return signature.toByteArray();
    }

    static String getSignatureHashAlgorithmName(String sshAlgorithmName) throws NoSuchAlgorithmException {
        switch (sshAlgorithmName) {
            case "ssh-rsa":
                return "SHA-1";
            case "rsa-sha256":
                return "SHA-256";
            case "rsa-sha512":
                return "SHA-256";
            case "ecdsa-sha2-nistp256":
                return "SHA-256";
            case "ecdsa-sha2-nistp384":
                return "SHA-384";
            case "ecdsa-sha2-nistp521":
                return "SHA-512";
            case "ssh-ed25519":
                return "SHA-256";
            default:
                throw new NoSuchAlgorithmException("Unknown ssh algorithm " + sshAlgorithmName);
        }
    }

    private static String getCurveName(ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException {
        return getCurveName(oid.getId());
    }

    private static String getCurveName(String curveOid) throws NoSuchAlgorithmException {
        // see RFC5656 section 10.{1,2}
        switch (curveOid) {
            // REQUIRED curves
            case "1.2.840.10045.3.1.7":
                return "nistp256";
            case "1.3.132.0.34":
                return "nistp384";
            case "1.3.132.0.35":
                return "nistp521";

            // RECOMMENDED curves
            case "1.3.132.0.1":
                return "1.3.132.0.1";
            case "1.2.840.10045.3.1.1":
                return "1.2.840.10045.3.1.1";
            case "1.3.132.0.33":
                return "1.3.132.0.33";
            case "1.3.132.0.26":
                return "1.3.132.0.26";
            case "1.3.132.0.27":
                return "1.3.132.0.27";
            case "1.3.132.0.16":
                return "1.3.132.0.16";
            case "1.3.132.0.36":
                return "1.3.132.0.36";
            case "1.3.132.0.37":
                return "1.3.132.0.37";
            case "1.3.132.0.38":
                return "1.3.132.0.38";

            default:
                throw new NoSuchAlgorithmException("Can't translate curve OID to SSH curve identifier");
        }
    }

    @AnyThread
    static String retrieveSshAlgorithmName(PublicKey publicKey) throws NoSuchAlgorithmException {
        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ASN1ObjectIdentifier curveOid = magicPublicKeyToCurveOid(ecPublicKey);
            String sshCurveName = SshUtil.getCurveName(curveOid);
            return "ecdsa-sha2-" + sshCurveName;
        }
        if (publicKey instanceof RSAPublicKey) {
            // "rsa-sha2-512"
            // "rsa-sha2-256"
            return "ssh-rsa";
        }
        throw new NoSuchAlgorithmException("Unknown key type for SSH auth: " + publicKey.getClass().getSimpleName());
    }

    @AnyThread
    static byte[] getSshPublicKeyBlob(PublicKey publicKey) throws NoSuchAlgorithmException {
        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ASN1ObjectIdentifier curveOid = magicPublicKeyToCurveOid(ecPublicKey);
            return SshUtil.encodeEcPublicKey(curveOid, ecPublicKey);
        }
        if (publicKey instanceof RSAPublicKey) {
            return SshUtil.encodeRsaPublicKey((RSAPublicKey) publicKey);
        }
        throw new NoSuchAlgorithmException("Unknown key type for SSH auth: " + publicKey.getClass().getSimpleName());
    }

    private static ASN1ObjectIdentifier magicPublicKeyToCurveOid(ECPublicKey ecPublicKey) throws NoSuchAlgorithmException {
        int fieldLength = ecPublicKey.getParams().getCurve().getField().getFieldSize();
        if (fieldLength == 256) {
            return SECObjectIdentifiers.secp256r1;
        } else if (fieldLength == 384) {
            return SECObjectIdentifiers.secp384r1;
        } else if (fieldLength == 521) {
            return SECObjectIdentifiers.secp521r1;
        } else {
            throw new NoSuchAlgorithmException("Unknown field size " + fieldLength + " for ECC key! (expecting 256, 384 or 521)");
        }
    }
}
