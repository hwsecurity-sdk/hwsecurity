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

package de.cotech.hw;


import androidx.annotation.WorkerThread;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;


/**
 * This use case class performs an "authenticate" operation on a challenge.
 * <p>
 * Instances of this class can be obtained from {@link SecurityKey} objects for Security Key types that support it.
 * For Security Keys that contain more than possible key for authentication operations, each instance of this class
 * is already associated with a specific key.
 * <p>
 * Example:
 * <pre>{@code
 * byte[] challenge = { (byte) 1, (byte) 2, (byte) 3, (byte) 4 };
 * PinProvider pinProvider = StaticPinProvider.getInstance(ByteSecret.unsafeFromString("123456"));
 *
 * SecurityKeyAuthenticator securityKeyAuthenticator = securityKey.createSecurityKeyAuthenticator(pinProvider)
 * byte[] signatureBytes = authenticator.authenticateWithDigest(challenge, "SHA-1");
 *
 * Signature signature = Signature.getInstance("SHA1withRSA");
 * signature.initVerify(securityKeyAuthenticator.retrievePublicKey());
 * signature.update(challenge);
 * boolean isVerified = signature.verify(signatureBytes);
 * assert isVerified;
 * }</pre>
 */
public interface SecurityKeyAuthenticator {
    /**
     * Authenticate a digest by signing it with the Security Key's authentication key.
     * <p>
     * Note that the hashAlgo parameter is required to correctly construct the PKCS1 padding, even though this method
     * does not do any hashing of its own. Valid values are "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
     * and "RIPEMD160".
     *
     * @param digest the digest to sign
     * @param hashAlgo the algorithm to digest the challenge with before signing
     */
    @WorkerThread
    byte[] authenticatePresignedDigest(byte[] digest, String hashAlgo) throws IOException;

    /**
     * Authenticate a challenge, by hashing it with the given hashing algorithm and signing it with the Security Key's
     * authentication key.
     * <p>
     * Valid values for hashAlgo are "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", and "RIPEMD160".
     *
     * @param challenge the challenge to sign
     * @param hashAlgo the algorithm to digest the challenge with before signing
     */
    @WorkerThread
    byte[] authenticateWithDigest(byte[] challenge, String hashAlgo) throws IOException, NoSuchAlgorithmException;

    /**
     * Retrieve the public key associated to this authenticator from the Security Key as a JCA PublicKey object.
     */
    @WorkerThread
    PublicKey retrievePublicKey() throws IOException;

    /**
     * Read associated certificate data from the Security Key.
     * <p>
     * What data is returned here depends on the type of Security Key, and may also be parametrized:
     * <ul>
     *     <li>For OpenPGP Security Keys, the returned data is typically the "certificate data" object from the card.</li>
     *     <li>
     *         For PIV Security Keys, it is commonly the associated certificate data,
     *         but may be changed to an arbitrary data object to cover special use cases.
     *     </li>
     * </ul>
     */
    @WorkerThread
    byte[] retrieveCertificateData() throws IOException;
}
