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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.OpenPgpCapabilities;
import de.cotech.hw.openpgp.OpenPgpCardUtils;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.openpgp.internal.openpgp.ECKeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.openpgp.PgpFingerprintCalculator;
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

    public void changeKey(KeyType keyType, String curveName, KeyPair keyPair, Date timestamp)
            throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("KeyPair given to uploadRsaKey must be ECC KeyPair!");
        }
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ASN1ObjectIdentifier curveOid = ECNamedCurveTable.getOID(curveName);
        if (curveOid == null) {
            throw new IllegalArgumentException("Curve name must be valid ECC named curve!");
        }

        changeKey(keyType, curveOid, timestamp, ecPrivateKey, ecPublicKey);
    }

    private void changeKey(KeyType keyType, ASN1ObjectIdentifier curveOid, Date timestamp, ECPrivateKey ecPrivateKey,
            ECPublicKey ecPublicKey) throws IOException {
        uploadEccKey(keyType, curveOid, ecPrivateKey, ecPublicKey);

        byte[] fingerprint = PgpFingerprintCalculator.calculateEccFingerprint(ecPublicKey, curveOid, timestamp);
        connection.setKeyMetadata(keyType, timestamp, fingerprint);
    }

    private void uploadEccKey(KeyType keyType, ASN1ObjectIdentifier curveOid, ECPrivateKey ecPrivateKey,
            ECPublicKey ecPublicKey) throws IOException {
        byte[] keyBytes = prepareKeyBytes(keyType, curveOid, ecPrivateKey, ecPublicKey);

        CommandApdu apdu = connection.getCommandFactory().createPutKeyCommand(keyBytes);
        connection.communicateOrThrow(apdu);
    }

    private byte[] prepareKeyBytes(KeyType keyType, ASN1ObjectIdentifier curveOid,
            ECPrivateKey ecPrivateKey, ECPublicKey ecPublicKey) throws IOException {
        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat currentFormat = openPgpCapabilities.getFormatForKeyType(keyType);
        ECKeyFormat requestedKeyFormat;
        if (keyType == KeyType.ENCRYPT) {
            requestedKeyFormat = ECKeyFormat.getInstanceECDHwithOid(curveOid);
        } else {
            requestedKeyFormat = ECKeyFormat.getInstanceECDSAwithOid(curveOid);
        }

        boolean requiresFormatChange = !requestedKeyFormat.equals(currentFormat);
        if (requiresFormatChange && openPgpCapabilities.isAttributesChangable()) {
            HwTimber.d("Setting key format");
            setKeyAttributes(keyType, requestedKeyFormat);
        } else if (requiresFormatChange) {
            throw new IOException("Different RSA format required, but applet doesn't support format change!");
        } else {
            HwTimber.d("Key format compatible, leaving as is");
        }

        return OpenPgpCardUtils.createECPrivKeyTemplate(ecPrivateKey, ecPublicKey, keyType, requestedKeyFormat);
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

    public void generateKey(KeyType keyType, ASN1ObjectIdentifier curveOid) throws IOException {
        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat currentFormat = openPgpCapabilities.getFormatForKeyType(keyType);
        ECKeyFormat requestedKeyFormat;
        if (keyType == KeyType.ENCRYPT) {
            requestedKeyFormat = ECKeyFormat.getInstanceECDHwithOid(curveOid);
        } else {
            requestedKeyFormat = ECKeyFormat.getInstanceECDSAwithOid(curveOid);
        }

        boolean requiresFormatChange = !requestedKeyFormat.equals(currentFormat);
        if (requiresFormatChange && openPgpCapabilities.isAttributesChangable()) {
            HwTimber.d("Setting key format");
            setKeyAttributes(keyType, requestedKeyFormat);
        } else if (requiresFormatChange) {
            throw new IOException("Different RSA format required, but applet doesn't support format change!");
        } else {
            HwTimber.d("Key format compatible, leaving as is");
        }

        CommandApdu command = connection.getCommandFactory().createGenerateKeyCommand(keyType.getSlot());
        connection.communicateOrThrow(command);
    }
}
