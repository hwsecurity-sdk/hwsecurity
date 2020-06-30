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
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.OpenPgpCapabilities;
import de.cotech.hw.openpgp.OpenPgpCardUtils;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.openpgp.PgpFingerprintCalculator;
import de.cotech.hw.openpgp.internal.openpgp.RSAKeyFormat;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class ChangeKeyRsaOp {
    private final OpenPgpAppletConnection connection;

    public static ChangeKeyRsaOp create(OpenPgpAppletConnection stConnection) {
        return new ChangeKeyRsaOp(stConnection);
    }

    private ChangeKeyRsaOp(OpenPgpAppletConnection connection) {
        this.connection = connection;
    }

    public byte[] changeKey(KeyType keyType, KeyPair keyPair, Date creationTime) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        if (!(privateKey instanceof RSAPrivateCrtKey) || !(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("KeyPair given to uploadRsaKey must be RSA KeyPair!");
        }
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        return changeKey(keyType, rsaPublicKey, rsaPrivateCrtKey, creationTime);
    }

    private byte[] changeKey(KeyType keyType, RSAPublicKey rsaPublicKey,
            RSAPrivateCrtKey rsaPrivateCrtKey, Date creationTime) throws IOException {
        uploadRsaKey(keyType, rsaPrivateCrtKey);

        byte[] fingerprint = PgpFingerprintCalculator.calculateRsaFingerprint(rsaPublicKey, creationTime);
        connection.setKeyMetadata(keyType, creationTime, fingerprint);

        return fingerprint;
    }

    private void uploadRsaKey(KeyType keyType, RSAPrivateCrtKey rsaPrivateCrtKey) throws IOException {
        byte[] keyBytes = prepareKeyBytes(keyType, rsaPrivateCrtKey);

        CommandApdu apdu = connection.getCommandFactory().createPutKeyCommand(keyBytes);
        connection.communicateOrThrow(apdu);
    }

    private byte[] prepareKeyBytes(KeyType keyType, RSAPrivateCrtKey rsaPrivateCrtKey) throws IOException {
        OpenPgpCapabilities openPgpCapabilities = connection.getOpenPgpCapabilities();
        KeyFormat currentFormat = openPgpCapabilities.getFormatForKeyType(keyType);
        RSAKeyFormat requestedKeyFormat;
        if (currentFormat instanceof RSAKeyFormat) {
            requestedKeyFormat = ((RSAKeyFormat) currentFormat).withModulus(2048);
        } else {
            requestedKeyFormat = RSAKeyFormat.getDefault2048BitFormat();
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

        return OpenPgpCardUtils.createRSAPrivKeyTemplate(rsaPrivateCrtKey, keyType, requestedKeyFormat);
    }

    private void setKeyAttributes(KeyType keyType, KeyFormat keyFormat) throws IOException {
        HwTimber.d("Setting key attributes for slot #%s to %s", keyType.getSlot(), keyFormat.toString());
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
}
