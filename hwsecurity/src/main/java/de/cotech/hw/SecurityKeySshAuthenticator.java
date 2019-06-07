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


import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import androidx.annotation.NonNull;

public interface SecurityKeySshAuthenticator {
    /**
     * Authenticate a challenge with the Security Key's authentication key.
     *
     * <p>
     * The input is expected to be the SSH encoded data to sign for a SSH_MSG_USERAUTH_REQUEST request as specified in
     * <a href="https://tools.ietf.org/html/rfc4252#section-7">RFC 4252, Section 7</a>. The "public key algorithm name"
     * of this request should be obtained from {@link #getSshPublicKeyAlgorithmName}. The data should <i>not</i> be hashed, as
     * hashing will be performed internally.
     *
     * <p>
     * The format of the returned output conforms to the OpenSSH "signature" format, see
     * <a href="https://tools.ietf.org/html/rfc4253#section-6.6">RFC 4253, Section 6.6</a>. It can be used directly
     * as the "signature" String value in the SSH_MSG_USERAUTH_REQUEST message, see
     * <a href="https://tools.ietf.org/html/rfc4252#section-7">RFC 4252, Section 7</a>.
     *
     * @param challenge the challenge to sign
     */
    @NonNull
    byte[] authenticateSshChallenge(byte[] challenge) throws IOException, NoSuchAlgorithmException;

    /**
     * Returns the public key associated with the security key.
     * <p>
     * The format of the returned output conforms to the OpenSSH "key/certificate data" format, as referred to in
     * <a href="https://tools.ietf.org/html/rfc4253#section-6.6">RFC 4253, Section 6.6</a>. It can be used directly
     * as the "key/certificate data" value in the SSH_MSG_USERAUTH_REQUEST message, see
     * <a href="https://tools.ietf.org/html/rfc4252#section-7">RFC 4252, Section 7</a>.
     */
    @NonNull
    byte[] getSshPublicKeyBlob();

    /**
     * Returns the public key associated with the security key, encoded as a string.
     * <p>
     * This format is commonly found in openssh public key (".pub") files. It is ascii-encoded, and includes the
     * algorithm name ({@link #getSshPublicKeyAlgorithmName()}) plus the base 64 encoded public key blob
     * ({@link #getSshPublicKeyBlob()}). For example:
     * <p>
     * <pre>ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKVzhwo9s+G2DrqxQDta5Af1Ro7mQolaKTOOqIPtrGjUVRYOLzo3s3FcFyWcysjeIfJ93SVMs9w95vwlUxR1Bcs=</pre>
     */
    @NonNull
    String getSshPublicKeyString();

    /**
     * Returns the algorithm name of the public key associated with the security key.
     * <p>
     * This will be "ssh-rsa" for an RSA key, or "ecdsa-sha2-nistp256" for a P-256 key. If the public key is an openssh
     * certificate rather than a simple public key, it will have a "-cert-v01@openssh.com" suffix.
     */
    @NonNull
    String getSshPublicKeyAlgorithmName();

    /**
     * Returns the algorithm name of the signature algorithm associated with the security key.
     * <p>
     * This will be "ssh-rsa" for an RSA key, or "ecdsa-sha2-nistp256" for a P-256 key. Unlike
     * {@link #getSshPublicKeyAlgorithmName()}, this method returns the same value for certificates
     * and simple public keys.
     */
    @NonNull
    String getSshSignatureAlgorithmName();
}
