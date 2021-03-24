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

package de.cotech.hw.openpgp.internal.operations;


import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.OpenPgpCapabilities;
import de.cotech.hw.openpgp.internal.OpenPgpCardUtils;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.openpgp.internal.openpgp.EcKeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.openpgp.Rfc4880FingerprintCalculator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;

import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class ChangeKeyEccOp {
    private final OpenPgpAppletConnection connection;

    public static ChangeKeyEccOp create(OpenPgpAppletConnection stConnection) {
        return new ChangeKeyEccOp(stConnection);
    }

    private ChangeKeyEccOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    public byte[] changeKey(KeyType keyType, String curveName, KeyPair keyPair, Date creationTime)
            throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("KeyPair given to changeKey must be ECC KeyPair!");
        }
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ASN1ObjectIdentifier curveOid = ECNamedCurveTable.getOID(curveName);
        if (curveOid == null) {
            throw new IllegalArgumentException("Curve name must be valid ECC named curve!");
        }

        byte[] keyBytes = prepareKeyBytes(keyType, curveOid, ecPrivateKey, ecPublicKey);
        CommandApdu apdu = connection.getCommandFactory().createPutKeyCommand(keyBytes);
        connection.communicateOrThrow(apdu);

        return setKeyMetadata(keyType, ecPublicKey, curveOid, creationTime);
    }

    private byte[] setKeyMetadata(KeyType keyType, PublicKey publicKey,
                                  ASN1ObjectIdentifier curveOid, Date timestamp) throws IOException {
        EcKeyFormat requestedKeyFormat = EcKeyFormat.getInstanceForKeyGeneration(keyType, curveOid);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateEccFingerprint(publicKey, requestedKeyFormat, timestamp);
        connection.setKeyMetadata(keyType, timestamp, fingerprint);

        return fingerprint;
    }

    private byte[] prepareKeyBytes(KeyType keyType, ASN1ObjectIdentifier curveOid,
                                   ECPrivateKey ecPrivateKey, ECPublicKey ecPublicKey) throws IOException {
        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat currentFormat = openPgpCapabilities.getFormatForKeyType(keyType);
        EcKeyFormat requestedKeyFormat = EcKeyFormat.getInstanceForKeyGeneration(keyType, curveOid);

        boolean requiresFormatChange = !requestedKeyFormat.equals(currentFormat);
        if (requiresFormatChange && openPgpCapabilities.isAttributesChangable()) {
            HwTimber.d("Setting key format");
            setKeyAttributes(keyType, requestedKeyFormat);
        } else if (requiresFormatChange) {
            throw new IOException("Different ECC format required, but applet doesn't support format change!");
        } else {
            HwTimber.d("Key format compatible, leaving as is");
        }

        return OpenPgpCardUtils.createEcPrivKeyTemplate(ecPrivateKey, ecPublicKey, keyType, requestedKeyFormat);
    }

    private void setKeyAttributes(KeyType keyType, KeyFormat keyFormat) throws IOException {
        HwTimber.d("Setting key attributes for slot 0x%x to %s", keyType.getAlgoAttributeSlot(), keyFormat.toString());
        putData(keyType.getAlgoAttributeSlot(), keyFormat.toBytes(keyType));
        connection.refreshConnectionCapabilities();
    }

    private void putData(int dataObject, byte[] data) throws IOException {
        if (data.length > 254) {
            throw new IOException("Cannot PUT DATA with length > 254");
        }

        CommandApdu command = connection.getCommandFactory().createPutDataCommand(dataObject, data);
        connection.communicateOrThrow(command);
    }

    public PublicKey generateKey(KeyType keyType, ASN1ObjectIdentifier curveOid, Date creationTime) throws IOException {
        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat currentFormat = openPgpCapabilities.getFormatForKeyType(keyType);
        EcKeyFormat requestedKeyFormat = EcKeyFormat.getInstanceForKeyGeneration(keyType, curveOid);

        boolean requiresFormatChange = !requestedKeyFormat.equals(currentFormat);
        if (requiresFormatChange && openPgpCapabilities.isAttributesChangable()) {
            HwTimber.d("Setting key format");
            setKeyAttributes(keyType, requestedKeyFormat);
        } else if (requiresFormatChange) {
            throw new IOException("Different key format required, but applet doesn't support format change!");
        } else {
            HwTimber.d("Key format compatible, leaving as is");
        }

        CommandApdu command = connection.getCommandFactory().createGenerateKeyCommand(keyType.getSlot());
        ResponseApdu response = connection.communicateOrThrow(command);

        byte[] publicKeyBytes = response.getData();
        PublicKey publicKey = requestedKeyFormat.getKeyFormatParser().parseKey(publicKeyBytes);

        byte[] fingerprint = setKeyMetadata(keyType, publicKey, curveOid, creationTime);

        return publicKey;
    }
}
