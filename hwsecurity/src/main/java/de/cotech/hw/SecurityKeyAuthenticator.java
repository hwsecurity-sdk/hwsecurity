/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * This use case class performs an "authenticate" operation on a challenge.
 * <p>
 * This class performs the authenticate operation with whatever security key it is passed, doing no checks to ensure
 * it matches an some expected key. This is useful for workflows where the security key isn't set up on the same device
 * that uses it.
 * <p>
 * Example:
 * <pre>{@code
 * byte[] challenge = { (byte) 1, (byte) 2, (byte) 3, (byte) 4 };
 * PairedAuthenticator authenticator = new SecurityKeyAuthenticator(keyInteractor, pairedPinProvider)
 * byte[] signatureBytes = authenticator.authenticateWithDigest(challenge, "SHA-1");
 *
 * Signature signature = Signature.getInstance("SHA1withRSA");
 * signature.initVerify(authPublicKey);
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
}
