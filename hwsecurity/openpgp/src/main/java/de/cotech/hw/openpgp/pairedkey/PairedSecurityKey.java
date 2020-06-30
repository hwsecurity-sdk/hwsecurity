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


import java.io.Serializable;
import java.security.PublicKey;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


/**
 * A PairedSecurityKey represents a storable reference to a hardware security key that has been paired
 * before.
 * <p>
 * Specifically, it contains the security key's AID, and public keys for key pairs stored on the security key.
 * The AID (Application Identifier) contains a unique serial number, which can be used to identify its related
 * security key when it connects.
 * <p>
 * This class is primarily used for two use cases:
 * <ul>
 *     <li>Recognize a security key that has been paired before upon connection.</li>
 *     <li>Perform public operations on the security key's key pairs.</li>
 * </ul>
 * <p>
 * This class is a serializable POJO, and instances can be stored in a
 * {@link de.cotech.hw.openpgp.storage.PairedSecurityKeyStorage}, or any storage that supports {@link Serializable}
 * objects.
 *
 * @see de.cotech.hw.openpgp.storage.PairedSecurityKeyStorage
 *
 */
public class PairedSecurityKey implements Serializable {
    private static final long serialVersionUID = 1573018456341217789L;

    private final byte[] securityKeyAid;
    private final byte[] encryptFingerprint;
    private final PublicKey encryptPublicKey;
    private final byte[] signFingerprint;
    private final PublicKey signPublicKey;
    private final byte[] authFingerprint;
    private final PublicKey authPublicKey;

    /**
     * Constructs a new PairedSecurityKey.
     *
     * This method should only be used internally.
     */
    @RestrictTo(Scope.LIBRARY_GROUP)
    public PairedSecurityKey(byte[] securityKeyAid,
            byte[] encryptFingerprint, PublicKey encryptPublicKey,
            byte[] signFingerprint, PublicKey signPublicKey,
            byte[] authFingerprint, PublicKey authPublicKey) {
        this.securityKeyAid = securityKeyAid;
        this.encryptFingerprint = encryptFingerprint;
        this.encryptPublicKey = encryptPublicKey;
        this.signFingerprint = signFingerprint;
        this.signPublicKey = signPublicKey;
        this.authFingerprint = authFingerprint;
        this.authPublicKey = authPublicKey;
    }

    /**
     * Returns the security key's AID (Application Identifier).
     */
    public byte[] getSecurityKeyAid() {
        return securityKeyAid;
    }

    /**
     * Returns the fingerprint of the encryption key stored on the paired security key.
     *
     * This fingerprint corresponds to an OpenPGP fingerprint. It is used internally to
     * ensure the public and private key material match during operations, but should
     * not be used normally.
     */
    public byte[] getEncryptFingerprint() {
        return encryptFingerprint;
    }
    public byte[] getSignFingerprint() {
        return signFingerprint;
    }
    public byte[] getAuthFingerprint() {
        return authFingerprint;
    }

    /**
     * Returns the encryption key stored on the paired security key.
     *
     * This will typically be an RSA 2048 bit key. In the future, this might be changed to internally use
     * a P-256 ECC (elliptic curve cryptography) key if the security key supports it.
     */
    public PublicKey getEncryptPublicKey() {
        return encryptPublicKey;
    }
    public PublicKey getSignPublicKey() {
        return signPublicKey;
    }
    public PublicKey getAuthPublicKey() {
        return authPublicKey;
    }
}
