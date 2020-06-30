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


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.internal.openpgp.ECKeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


/** This class implements the PSO:DECIPHER operation, as specified in OpenPGP card spec / 7.2.11 (p52 in v3.0.1).
 *
 * See https://www.g10code.com/docs/openpgp-card-3.0.pdf
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class PsoDecryptOp {
    public static final ASN1ObjectIdentifier CV25519 = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029.1.5.1");

    private final OpenPgpAppletConnection connection;

    public static PsoDecryptOp create(OpenPgpAppletConnection connection) {
        return new PsoDecryptOp(connection);
    }

    private PsoDecryptOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    public byte[] verifyAndDecryptSessionKey(ByteSecret pin,
            @NonNull byte[] encryptedSessionKeyMpi,
            int securityKeySymmetricKeySize, byte[] userKeyingMaterial)
            throws IOException {
        connection.verifyPinForOther(pin);

        KeyFormat kf = connection.getOpenPgpCapabilities().getEncryptKeyFormat();
        switch (kf.keyFormatType()) {
            case RSAKeyFormatType:
                return decryptSessionKeyRsa(encryptedSessionKeyMpi);

            case ECKeyFormatType:
                return decryptSessionKeyEcdh(encryptedSessionKeyMpi, (ECKeyFormat) kf,
                        securityKeySymmetricKeySize, userKeyingMaterial);

            default:
                throw new IOException("Unknown encryption key type!");
        }
    }

    public byte[] simpleDecryptSessionKeyRsa(ByteSecret pin,
            byte[] encryptedSessionKey) throws IOException {
        connection.verifyPinForOther(pin);

        byte[] psoDecipherPayload = Arrays.prepend(encryptedSessionKey, (byte) 0x00);

        CommandApdu command = connection.getCommandFactory().createDecipherCommand(psoDecipherPayload, encryptedSessionKey.length);
        ResponseApdu response = connection.communicateOrThrow(command);

        return response.getData();
    }

    private byte[] decryptSessionKeyRsa(byte[] encryptedSessionKeyMpi) throws IOException {
        int mpiLength = getMpiLength(encryptedSessionKeyMpi);
        byte[] psoDecipherPayload = getRsaOperationPayload(encryptedSessionKeyMpi);

        CommandApdu command = connection.getCommandFactory().createDecipherCommand(psoDecipherPayload, mpiLength);
        ResponseApdu response = connection.communicateOrThrow(command);

        return response.getData();
    }

    @VisibleForTesting
    public byte[] getRsaOperationPayload(byte[] encryptedSessionKeyMpi) throws IOException {
        int mpiLength = getMpiLength(encryptedSessionKeyMpi);
        if (mpiLength != encryptedSessionKeyMpi.length - 2) {
            throw new IOException("Malformed RSA session key!");
        }

        byte[] psoDecipherPayload = new byte[mpiLength + 1];
        psoDecipherPayload[0] = 0x00; // RSA Padding Indicator Byte
        System.arraycopy(encryptedSessionKeyMpi, 2, psoDecipherPayload, 1, mpiLength);
        return psoDecipherPayload;
    }

    private byte[] decryptSessionKeyEcdh(byte[] encryptedSessionKeyMpi, ECKeyFormat eckf,
            int securityKeySymmetricKeySize, byte[] userKeyingMaterial)
            throws IOException {
        int mpiLength = getMpiLength(encryptedSessionKeyMpi);
        byte[] encryptedPoint = Arrays.copyOfRange(encryptedSessionKeyMpi, 2, mpiLength + 2);

        byte[] psoDecipherPayload = getEcDecipherPayload(eckf, encryptedPoint);

        byte[] dataLen;
        if (psoDecipherPayload.length < 128) {
            dataLen = new byte[]{(byte) psoDecipherPayload.length};
        } else {
            dataLen = new byte[]{(byte) 0x81, (byte) psoDecipherPayload.length};
        }
        psoDecipherPayload = Arrays.concatenate(Hex.decode("86"), dataLen, psoDecipherPayload);

        if (psoDecipherPayload.length < 128) {
            dataLen = new byte[]{(byte) psoDecipherPayload.length};
        } else {
            dataLen = new byte[]{(byte) 0x81, (byte) psoDecipherPayload.length};
        }
        psoDecipherPayload = Arrays.concatenate(Hex.decode("7F49"), dataLen, psoDecipherPayload);

        if (psoDecipherPayload.length < 128) {
            dataLen = new byte[]{(byte) psoDecipherPayload.length};
        } else {
            dataLen = new byte[]{(byte) 0x81, (byte) psoDecipherPayload.length};
        }
        psoDecipherPayload = Arrays.concatenate(Hex.decode("A6"), dataLen, psoDecipherPayload);

        CommandApdu command = connection.getCommandFactory().createDecipherCommand(
                psoDecipherPayload, encryptedPoint.length);
        ResponseApdu response = connection.communicateOrThrow(command);

        /* From 3.x OpenPGP card specification :
           In case of ECDH the card supports a partial decrypt only.
           With its own private key and the given public key the card calculates a shared secret
           in compliance with the Elliptic Curve Key Agreement Scheme from Diffie-Hellman.
           The shared secret is returned in the response, all other calculation for deciphering
           are done outside of the card.

           The shared secret obtained is a KEK (Key Encryption Key) that is used to wrap the
           session key.

           From rfc6637#section-13 :
           This document explicitly discourages the use of algorithms other than AES as a KEK algorithm.
       */
        byte[] keyEncryptionKey = response.getData();

        final byte[] keyEnc = new byte[encryptedSessionKeyMpi[mpiLength + 2]];

        System.arraycopy(encryptedSessionKeyMpi, 2 + mpiLength + 1, keyEnc, 0, keyEnc.length);

        try {
            final MessageDigest kdf = MessageDigest.getInstance("SHA-256");

            kdf.update(new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 1});
            kdf.update(keyEncryptionKey);
            kdf.update(userKeyingMaterial);

            byte[] kek = kdf.digest();
            Cipher c = Cipher.getInstance("AESWrap");

            c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, 0, securityKeySymmetricKeySize / 8, "AES"));

            Key paddedSessionKey = c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY);

            Arrays.fill(kek, (byte) 0);

            return unpadSessionData(paddedSessionKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Unknown digest/encryption algorithm!");
        } catch (NoSuchPaddingException e) {
            throw new IOException("Unknown padding algorithm!");
        } catch (InvalidKeyException e) {
            throw new IOException("Invalid KEK key!");
        }
    }

    private static byte[] unpadSessionData(byte[] encoded) throws IOException {
        byte padValue = encoded[encoded.length - 1];

        for (int i = encoded.length - padValue; i != encoded.length; i++) {
            if (encoded[i] != padValue) {
                throw new IOException("bad padding found in session data");
            }
        }

        byte[] taggedKey = new byte[encoded.length - padValue];

        System.arraycopy(encoded, 0, taggedKey, 0, taggedKey.length);

        return taggedKey;
    }

    private byte[] getEcDecipherPayload(ECKeyFormat eckf, byte[] encryptedPoint) throws IOException {
        if (CV25519.equals(eckf.getCurveOID())) {
            return Arrays.copyOfRange(encryptedPoint, 1, 33);
        } else {
            X9ECParameters x9Params = ECNamedCurveTable.getByOID(eckf.getCurveOID());
            ECPoint p = x9Params.getCurve().decodePoint(encryptedPoint);
            if (!p.isValid()) {
                throw new IOException("Invalid EC point!");
            }

            return p.getEncoded(false);
        }
    }

    private int getMpiLength(byte[] multiPrecisionInteger) {
        return ((((multiPrecisionInteger[0] & 0xff) << 8) + (multiPrecisionInteger[1] & 0xff)) + 7) / 8;
    }
}
