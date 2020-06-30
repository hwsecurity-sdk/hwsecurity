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

package de.cotech.hw.piv;


import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.piv.internal.operations.GeneralAuthenticateOp;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.PinProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class PivSecurityKeyAuthenticator implements SecurityKeyAuthenticator {
    private final PivSecurityKey pivSecurityKey;
    private final PinProvider pairedPinProvider;
    private final PivKeyReference keyReference;
    private final String certificateDataObjectHex;

    PivSecurityKeyAuthenticator(
            PivSecurityKey pivSecurityKey, PinProvider pairedPinProvider, PivKeyReference authentication, String certificateDataObjectHex) {
        this.pivSecurityKey = pivSecurityKey;
        this.pairedPinProvider = pairedPinProvider;
        this.keyReference = authentication;
        this.certificateDataObjectHex = certificateDataObjectHex;
    }

    @WorkerThread
    public byte[] authenticatePresignedDigest(byte[] digest, String hashAlgo) throws IOException {
        ByteSecret pairedPin = pairedPinProvider.getPin(pivSecurityKey.pivAppletConnection.getConnectedAppletAid());
        try {
            X509Certificate x509Certificate = pivSecurityKey.retrieveCertificate(keyReference);
            GeneralAuthenticateOp generalAuthenticateOp = GeneralAuthenticateOp.create(pivSecurityKey.pivAppletConnection, x509Certificate);
            return generalAuthenticateOp.calculateAuthenticationSignature(pairedPin, digest, hashAlgo, keyReference);
        } catch (CertificateException e) {
            throw new IOException(e);
        }

    }

    public byte[] authenticateWithDigest(byte[] challenge, String hashAlgo) throws IOException, NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance(hashAlgo).digest(challenge);
        return authenticatePresignedDigest(digest, hashAlgo);
    }

    @Override
    public PublicKey retrievePublicKey() throws IOException {
        try {
            return pivSecurityKey.retrieveCertificate(keyReference).getPublicKey();
        } catch (CertificateException e) {
            throw new IOException("Failed to retrieve public key from Security Key", e);
        }
    }

    @Override
    public byte[] retrieveCertificateData() throws IOException {
        if (certificateDataObjectHex != null) {
            return pivSecurityKey.retrieveDataObject(certificateDataObjectHex);
        } else {
            return pivSecurityKey.retrieveCertificateData(keyReference);
        }
    }

}
