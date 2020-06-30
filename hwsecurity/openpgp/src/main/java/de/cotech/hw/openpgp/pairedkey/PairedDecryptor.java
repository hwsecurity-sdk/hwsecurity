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

package de.cotech.hw.openpgp.pairedkey;


import java.io.IOException;

import de.cotech.hw.openpgp.OpenPgpSecurityKey;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.openpgp.internal.operations.PsoDecryptOp;
import de.cotech.hw.openpgp.pairedkey.PairedEncryptor;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKey;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKeyException;
import de.cotech.hw.secrets.PinProvider;


/**
 * This use case class performs a "decrypt" operation on encrypted data, parametrized by a
 * {@link OpenPgpSecurityKey}, {@link PinProvider}, and {@link PairedSecurityKey}.
 * <p>
 * <pre>{@code
 * PairedSecurityKey pairedSecurityKey = pairedSecurityTokenStorage.getPairedSecurityKey(keyInteractor.getSecurityKeyAid());
 * PairedDecryptor decryptor = PairedDecryptor(keyInteractor, pairedPinProvider, pairedSecurityToken);
 * byte[] encryptedSessionSecret = encryptedSessionStorage.getEncryptedSessionSecret(pairedSecurityToken.getSecurityKeyAid());
 *
 * ByteSecret sessionSecret = decryptor.decryptSessionSecret(encryptedSessionSecret);
 * }</pre>
 * <p>
 * This <code>sessionSecret</code> can be used for symmetric encryption operations, e.g. to encrypt a database.
 *
 * @see PairedEncryptor
 *
 */
public class PairedDecryptor {
    private final OpenPgpSecurityKey openPgpSecurityKey;
    private final PinProvider pinProvider;
    private final PairedSecurityKey pairedSecurityKey;

    /**
     * Create an instance parametrized with a {@link OpenPgpSecurityKey}, {@link PinProvider}, and
     * {@link PairedSecurityKey}.
     */
    public PairedDecryptor(OpenPgpSecurityKey openPgpSecurityKey, PinProvider pinProvider, PairedSecurityKey pairedSecurityKey) {
        this.openPgpSecurityKey = openPgpSecurityKey;
        this.pinProvider = pinProvider;
        this.pairedSecurityKey = pairedSecurityKey;
    }

    /**
     * Decrypts data using the injected {@link OpenPgpSecurityKey}, {@link PinProvider}, and
     * {@link PairedSecurityKey}.
     *
     * @param encryptedData the data to decrypt
     *
     * @throws IOException if communication with the card failed
     * @throws PairedSecurityKeyException if the connected security key doesn't match the paired one
     */
    public ByteSecret decryptSessionSecret(byte[] encryptedData) throws IOException {
        if (!openPgpSecurityKey.matchesPairedSecurityKey(pairedSecurityKey)) {
            throw new PairedSecurityKeyException();
        }

        ByteSecret pairedPin = pinProvider.getPin(openPgpSecurityKey.getOpenPgpInstanceAid());

        PsoDecryptOp psoDecryptOp = PsoDecryptOp.create(openPgpSecurityKey.openPgpAppletConnection);
        byte[] secret = psoDecryptOp.simpleDecryptSessionKeyRsa(pairedPin, encryptedData);
        return ByteSecret.fromByteArrayTakeOwnership(secret);
    }

}
