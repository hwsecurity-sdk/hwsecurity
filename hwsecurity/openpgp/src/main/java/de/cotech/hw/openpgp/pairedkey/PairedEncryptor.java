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


import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import de.cotech.hw.openpgp.storage.EncryptedSessionStorage;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.openpgp.util.RsaEncryptionUtil;


/**
 * This use case class performs an "encrypt" operation on some data, parametrized by a {@link PairedSecurityKey}.
 * <p>
 * <pre>{@code
 * ByteSecret sessionSecret = SecretGenerator.getInstance().createRandom(32);
 * byte[] encryptedSessionSecret = new PairedEncryptor(pairedSecurityKey).encrypt(sessionSecret);
 * }</pre>
 * <p>
 * The <code>encryptedSessionSecret</code> is typically stored in an
 * {@link EncryptedSessionStorage}, to be able to later restore the
 * <code>sessionSecret</code> using a {@link PairedDecryptor}.
 * <p>
 * The <code>sessionSecret</code> can be used for symmetric encryption operations, e.g. to encrypt a database. Once
 * it has been deleted, it can only be restored from the <code>encryptedSessionSecret</code> when the paired security
 * key is connected.
 *
 * @see PairedDecryptor
 *
 */
public class PairedEncryptor {
    private final PairedSecurityKey pairedSecurityKey;
    private final RsaEncryptionUtil rsaEncryptionUtil = new RsaEncryptionUtil();

    /**
     * Create an instance parametrized for a {@link PairedSecurityKey}.
     */
    public PairedEncryptor(PairedSecurityKey pairedSecurityKey) {
        this.pairedSecurityKey = pairedSecurityKey;
    }

    /**
     * Encrypts data for the injected {@link PairedSecurityKey}.
     *
     * @param data the data to encrypt
     */
    public byte[] encrypt(ByteSecret data) {
        byte[] secretBytes = null;
        try {
            secretBytes = data.unsafeGetByteCopy();
            return rsaEncryptionUtil.encryptWithRsaPublicKey(secretBytes, (RSAPublicKey) pairedSecurityKey.getEncryptPublicKey());
        } finally {
            if (secretBytes != null) Arrays.fill(secretBytes, (byte) 0);
        }
    }
}
