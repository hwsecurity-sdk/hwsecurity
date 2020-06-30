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


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.piv.PivKeyReference;
import de.cotech.hw.piv.internal.PivAppletConnection;
import de.cotech.hw.piv.internal.PivCommandApduFactory;
import de.cotech.hw.secrets.ByteSecret;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;


@RestrictTo(Scope.LIBRARY_GROUP)
public class GeneralAuthenticateOp {
    private final PivAppletConnection connection;
    private X509Certificate x509Certificate;
    private final PivSignatureUtils signatureUtils = PivSignatureUtils.getInstance();

    public static GeneralAuthenticateOp create(PivAppletConnection pivAppletConnection, X509Certificate x509Certificate) {
        return new GeneralAuthenticateOp(pivAppletConnection, x509Certificate);
    }

    private GeneralAuthenticateOp(PivAppletConnection connection, X509Certificate x509Certificate) {
        this.connection = connection;
        this.x509Certificate = x509Certificate;
    }

    public byte[] calculateAuthenticationSignature(ByteSecret pin, byte[] digest, String hashAlgo, PivKeyReference keyRef)
            throws IOException {
        connection.verifyPin(pin);

        PublicKey publicKey = x509Certificate.getPublicKey();
        byte[] data = signatureUtils.prepareData(digest, publicKey, hashAlgo);

        CommandApdu command = getCommandApduForKey(connection.getCommandFactory(), keyRef, publicKey, data);
        ResponseApdu response = connection.communicateOrThrow(command);

        return signatureUtils.unpackSignatureData(response.getData());
    }

    private static CommandApdu getCommandApduForKey(PivCommandApduFactory commandFactory, PivKeyReference keyRef,
            PublicKey publicKey, byte[] data) throws IOException {
        if (publicKey instanceof RSAPublicKey) {
            return commandFactory.createGeneralAuthenticateRSA(keyRef.referenceId, data);
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            int fieldLength = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            if (fieldLength == 256) {
                return commandFactory.createGeneralAuthenticateP256(keyRef.referenceId, data);
            } else if (fieldLength == 384) {
                return commandFactory.createGeneralAuthenticateP384(keyRef.referenceId, data);
            } else {
                throw new IOException("Unknown field size " + fieldLength + " for ECC key! (expecting 256 or 384)");
            }
        }
        throw new IOException("Unknown certificate algorithm!");
    }

    /*
    // Sadly, the X509Certificate class offers no way to get the OID of the *signed* key, only the *signing* key.
    // That means we'll have to figure out the public key type differently :(
    private static CommandApdu getCommandApduForKey(PivCommandApduFactory commandFactory, PivKeyReference keyRef,
            ASN1ObjectIdentifier algoOid, byte[] data) throws IOException {
        if (algoOid.on(PKCSObjectIdentifiers.pkcs_1)) {
            return commandFactory.createGeneralAuthenticateRSA(keyRef.referenceId, data);
        } else if (algoOid.on(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
            if (data.length != 32) {
                throw new IOException("Invalid hash length for P-256 (must be 32 bytes)");
            }
            return commandFactory.createGeneralAuthenticateP256(keyRef.referenceId, data);
        } else if (algoOid.on(X9ObjectIdentifiers.ecdsa_with_SHA384)) {
            if (data.length != 48) {
                throw new IOException("Invalid hash length for P-384 (must be 48 bytes)");
            }
            return commandFactory.createGeneralAuthenticateP384(keyRef.referenceId, data);
        }
        throw new IOException("Unknown certificate algorithm OID!");
    }
    */
}
