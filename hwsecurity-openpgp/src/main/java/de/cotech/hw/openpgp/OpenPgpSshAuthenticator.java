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

package de.cotech.hw.openpgp;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import androidx.annotation.NonNull;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.SecurityKeySshAuthenticator;
import de.cotech.hw.openpgp.internal.ssh.SshUtil;


public class OpenPgpSshAuthenticator implements SecurityKeySshAuthenticator {
    private final SecurityKeyAuthenticator securityKeyAuthenticator;
    private final String sshPublicKeyAlgorithmName;
    private final byte[] sshPublicKeyBlob;

    public OpenPgpSshAuthenticator(SecurityKeyAuthenticator securityKeyAuthenticator,
                                        String sshPublicKeyAlgorithmName, byte[] sshPublicKeyBlob) {
        this.securityKeyAuthenticator = securityKeyAuthenticator;
        this.sshPublicKeyAlgorithmName = sshPublicKeyAlgorithmName;
        this.sshPublicKeyBlob = sshPublicKeyBlob;
    }

    @NonNull
    @Override
    public byte[] authenticateSshChallenge(byte[] challenge) throws IOException, NoSuchAlgorithmException {
        String signatureAlgorithmName = getSshSignatureAlgorithmName();
        String signatureHashAlgorithmName = SshUtil.getSignatureHashAlgorithmName(signatureAlgorithmName);

        byte[] signedChallenge = securityKeyAuthenticator.authenticateWithDigest(challenge, signatureHashAlgorithmName);

        return SshUtil.encodeSshSignature(signatureAlgorithmName, signedChallenge);
    }

    @NonNull
    @Override
    public byte[] getSshPublicKeyBlob() {
        return sshPublicKeyBlob;
    }

    @NonNull
    @Override
    public String getSshPublicKeyString() {
        return SshUtil.encodeKeyBlobAsKeyString(sshPublicKeyAlgorithmName, sshPublicKeyBlob);
    }

    @NonNull
    @Override
    public String getSshPublicKeyAlgorithmName() {
        return sshPublicKeyAlgorithmName;
    }

    @NonNull
    @Override
    public String getSshSignatureAlgorithmName() {
        return SshUtil.stripAlgorithmCertSuffix(getSshPublicKeyAlgorithmName());
    }
}
