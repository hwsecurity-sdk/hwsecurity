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


import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.SecurityKeyTlsClientCertificateAuthenticator;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.piv.internal.PivAppletConnection;
import de.cotech.hw.piv.internal.operations.ResetRetryCounterOp;
import de.cotech.hw.provider.CotechSecurityKeyProvider;
import de.cotech.hw.provider.SecurityKeyPrivateKey.SecurityKeyEcdsaPrivateKey;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.PinProvider;


@SuppressWarnings({"WeakerAccess", "unused"}) // public API
public class PivSecurityKey extends SecurityKey {
    final PivAppletConnection pivAppletConnection;

    private final HashMap<PivKeyReference, X509Certificate> certificateCache = new HashMap<>();

    public PivSecurityKey(SecurityKeyManagerConfig config, Transport transport, PivAppletConnection pivAppletConnection) {
        super(config, transport);
        this.pivAppletConnection = pivAppletConnection;
    }

    @NonNull
    public SecurityKeyTlsClientCertificateAuthenticator createSecurityKeyClientCertificateAuthenticator(
            @NonNull PinProvider pinProvider) throws IOException, CertificateException {
        X509Certificate cert = retrieveCertificate(PivKeyReference.AUTHENTICATION);
        PrivateKey privateKey = getJcaPrivateKeyForAuthentication(pinProvider);

        return SecurityKeyTlsClientCertificateAuthenticator.createFromPivAuthenticationCertificate(cert, privateKey);
    }

    public PrivateKey getJcaPrivateKeyForAuthentication(@NonNull PinProvider pinProvider) {
        return getJcaPrivateKeyForAuthentication(pinProvider, PivKeyReference.AUTHENTICATION);
    }

    public PrivateKey getJcaPrivateKeyForAuthentication(@NonNull PinProvider pinProvider, PivKeyReference authentication) {
        if (!CotechSecurityKeyProvider.isInstalled()) {
            throw new IllegalStateException("CotechSecurityProvider must be installed to use JCA private key operations!");
        }

        SecurityKeyAuthenticator securityKeyAuthenticator = createSecurityKeyAuthenticator(pinProvider, authentication);
        return new SecurityKeyEcdsaPrivateKey(securityKeyAuthenticator);
    }

    @AnyThread
    public SecurityKeyAuthenticator createSecurityKeyAuthenticator(PinProvider pinProvider) {
        return createSecurityKeyAuthenticator(pinProvider, PivKeyReference.AUTHENTICATION);
    }

    @AnyThread
    public SecurityKeyAuthenticator createSecurityKeyAuthenticator(PinProvider pinProvider, PivKeyReference keyReference) {
        return new PivSecurityKeyAuthenticator(this, pinProvider, keyReference, null);
    }

    @AnyThread
    public SecurityKeyAuthenticator createSecurityKeyAuthenticator(
            PinProvider pinProvider, PivKeyReference keyReference, @Nullable String certificateDataObjectHex) {
        return new PivSecurityKeyAuthenticator(this, pinProvider, keyReference, certificateDataObjectHex);
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @WorkerThread
    X509Certificate retrieveCertificate(PivKeyReference keyReference) throws IOException, CertificateException {
        X509Certificate cachedCertificate = certificateCache.get(keyReference);
        if (cachedCertificate != null) {
            return cachedCertificate;
        }

        byte[] certBytes = pivAppletConnection.retrieveCertificateBytes(keyReference);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        Certificate certificate = fact.generateCertificate(new ByteArrayInputStream(certBytes));
        if (certificate == null) {
            throw new IOException("Failed to decode X509 certificate!");
        }
        if (!(certificate instanceof X509Certificate)) {
            throw new IOException("Decoded certificate is not an X509 certificate!");
        }
        certificateCache.put(keyReference, (X509Certificate) certificate);
        return (X509Certificate) certificate;
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @WorkerThread
    byte[] retrieveDataObject(String dataObjectHex) throws IOException {
        return pivAppletConnection.getData(dataObjectHex);
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @WorkerThread
    byte[] retrieveCertificateData(PivKeyReference keyReference) throws IOException {
        return pivAppletConnection.retrieveCertificateBytes(keyReference);
    }

    @WorkerThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void updatePinUsingPuk(ByteSecret currentPuk, ByteSecret newPin) throws IOException {
        ResetRetryCounterOp modifyPinOp = ResetRetryCounterOp.create(pivAppletConnection);
        modifyPinOp.modifyPin(currentPuk, newPin);
    }
}
