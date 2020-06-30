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

package de.cotech.hw.provider;


import java.security.Provider;
import java.security.Security;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.util.HwTimber;


/**
 * This is a JCA cryptography Provider to interface with security keys via JCA.
 * <p>
 * This provider implements the underlying cryptographic operations for security key connected
 * {@link java.security.PrivateKey} objects. It must be initialized in the app before any JCA-based security key
 * operations can be performed. This is done as part of {@link de.cotech.hw.SecurityKeyManager#init} by
 * enabling JCA operations in the configuration parameter.
 *
 * @see de.cotech.hw.SecurityKeyManager
 *
 * @see SecurityKeyPrivateKey
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public final class CotechSecurityKeyProvider extends Provider {
    private static final String INFO = "Cotech Security Key Provider v0.1";
    public static final String PROVIDER_NAME = "CSK";

    public static void installProvider() {
        HwTimber.i("Installing JCA security provider for security key");
        int result = Security.addProvider(new CotechSecurityKeyProvider());
        if (result == -1) {
            HwTimber.d("provider was already installed");
        }
    }

    public static boolean isInstalled() {
        return Security.getProvider(CotechSecurityKeyProvider.PROVIDER_NAME) != null;
    }

    public CotechSecurityKeyProvider() {
        super(PROVIDER_NAME, 0.1, INFO);
        setup();
    }

    private void setup() {
        addAlgorithm("Signature.SHA1withRSA", "de.cotech.hw.provider.SecurityKeySignature$SHA1withRSA");
        addAlgorithm("Signature.SHA256withRSA", "de.cotech.hw.provider.SecurityKeySignature$SHA256withRSA");
        addAlgorithm("Signature.SHA384withRSA", "de.cotech.hw.provider.SecurityKeySignature$SHA384withRSA");
        addAlgorithm("Signature.SHA512withRSA", "de.cotech.hw.provider.SecurityKeySignature$SHA512withRSA");

        addAlgorithm("Signature.NONEwithECDSA", "de.cotech.hw.provider.SecurityKeySignature$NONEwithECDSA");
        addAlgorithm("Signature.SHA256withECDSA", "de.cotech.hw.provider.SecurityKeySignature$SHA256withECDSA");
        addAlgorithm("Signature.SHA384withECDSA", "de.cotech.hw.provider.SecurityKeySignature$SHA384withECDSA");
        addAlgorithm("Signature.SHA512withECDSA", "de.cotech.hw.provider.SecurityKeySignature$SHA512withECDSA");
    }

    private void addAlgorithm(String key, String value) {
        if (containsKey(key)) {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public boolean hasAlgorithm(String type, String name) {
        return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
    }
}
