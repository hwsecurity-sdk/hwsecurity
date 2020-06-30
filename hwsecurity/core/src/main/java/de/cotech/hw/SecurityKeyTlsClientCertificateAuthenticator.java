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


import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;


@RestrictTo(Scope.LIBRARY_GROUP)
public class SecurityKeyTlsClientCertificateAuthenticator {
    private final X509Certificate clientCertificate;
    private final PrivateKey privateKey;

    private SecurityKeyTlsClientCertificateAuthenticator(X509Certificate clientCertificate, PrivateKey privateKey) {
        this.clientCertificate = clientCertificate;
        this.privateKey = privateKey;
    }

    public static SecurityKeyTlsClientCertificateAuthenticator createFromPivAuthenticationCertificate(X509Certificate cert,
            PrivateKey privateKey) {
        return new SecurityKeyTlsClientCertificateAuthenticator(cert, privateKey);
    }


    public KeyManager buildKeyManager() {
        return new TrivialSingleKeyManager(new X509Certificate[]{ clientCertificate }, privateKey);
    }

    public SSLContext buildInitializedSslContext() throws KeyManagementException, NoSuchAlgorithmException {
        return buildInitializedSslContext(null);
    }

    public SSLContext buildInitializedSslContext(TrustManager[] trustManagers)
            throws NoSuchAlgorithmException, KeyManagementException {
        KeyManager clientCertificateKeyManager = buildKeyManager();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] { clientCertificateKeyManager }, trustManagers, null);
        return sslContext;
    }

    private static class TrivialSingleKeyManager extends X509ExtendedKeyManager {
        private static final String ALIAS = "singleton-alias";

        private final X509Certificate[] certChain;
        private final PrivateKey privateKey;

        TrivialSingleKeyManager(X509Certificate[] certChain, PrivateKey privateKey) {
            this.certChain = certChain;
            this.privateKey = privateKey;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] { ALIAS };
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return ALIAS;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return ALIAS;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            if (ALIAS.equals(alias)) {
                return certChain;
            } else {
                return null;
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            if (ALIAS.equals(alias)) {
                return privateKey;
            } else {
                return null;
            }
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return null;
        }
    }
}
