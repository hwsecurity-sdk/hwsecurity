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

package de.cotech.hw.openpgp;


import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.operations.InternalAuthenticateOp;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.PinProvider;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;


public class OpenPgpSecurityKeyAuthenticator implements SecurityKeyAuthenticator {
    private final OpenPgpSecurityKey openPgpSecurityKey;
    private final PinProvider pinProvider;

    /**
     * Create an instance parametrized with a {@link OpenPgpAppletConnection}, and a {@link PinProvider}.
     */
    OpenPgpSecurityKeyAuthenticator(OpenPgpSecurityKey openPgpSecurityKey, PinProvider pinProvider) {
        this.openPgpSecurityKey = openPgpSecurityKey;
        this.pinProvider = pinProvider;
    }

    public byte[] authenticatePresignedDigest(byte[] digest, String hashAlgo) throws IOException {
        ByteSecret pairedPin = pinProvider.getPin(openPgpSecurityKey.getOpenPgpInstanceAid());
        InternalAuthenticateOp psoDecryptOp = InternalAuthenticateOp.create(openPgpSecurityKey.openPgpAppletConnection);
        return psoDecryptOp.calculateAuthenticationSignature(pairedPin, digest, hashAlgo);
    }

    public byte[] authenticateWithDigest(byte[] challenge, String hashAlgo) throws IOException, NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance(hashAlgo).digest(challenge);
        return authenticatePresignedDigest(digest, hashAlgo);
    }

    @Override
    @WorkerThread
    public PublicKey retrievePublicKey() throws IOException {
        return openPgpSecurityKey.retrievePublicKey(KeyType.AUTH);
    }

    @Override
    @WorkerThread
    public byte[] retrieveCertificateData() throws IOException {
        return openPgpSecurityKey.readCertificateData();
    }
}
