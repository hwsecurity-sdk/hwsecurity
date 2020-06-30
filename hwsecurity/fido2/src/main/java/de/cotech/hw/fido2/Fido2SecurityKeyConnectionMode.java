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

package de.cotech.hw.fido2;


import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.async.Fido2AsyncOperationManager;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperationFactory;
import de.cotech.hw.fido2.internal.pinauth.PinAuthCryptoUtil;
import de.cotech.hw.fido2.internal.pinauth.PinProtocolV1;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;


public class Fido2SecurityKeyConnectionMode extends SecurityKeyConnectionMode<Fido2SecurityKey> {
    private static Fido2SecurityKeyConnectionMode INSTANCE;
    private final Fido2SecurityKeyConnectionModeConfig fido2Config;

    public static Fido2SecurityKeyConnectionMode getInstance() {
        if (INSTANCE == null) {
            Fido2SecurityKeyConnectionModeConfig defaultConfig =
                    Fido2SecurityKeyConnectionModeConfig.getDefaultConfig();
            INSTANCE = new Fido2SecurityKeyConnectionMode(
                    defaultConfig);
        }
        return INSTANCE;
    }

    public static Fido2SecurityKeyConnectionMode getInstance(Fido2SecurityKeyConnectionModeConfig  config) {
        return new Fido2SecurityKeyConnectionMode(config);
    }

    public Fido2SecurityKeyConnectionMode(Fido2SecurityKeyConnectionModeConfig fido2Config) {
        this.fido2Config = fido2Config;
    }

    @Override
    public Fido2SecurityKey establishSecurityKeyConnection(SecurityKeyManagerConfig config, Transport transport) throws IOException {
        if (!isRelevantTransport(transport)) {
            throw new IllegalArgumentException("Received incompatible transport!");
        }

        Fido2AppletConnection fido2AppletConnection = Fido2AppletConnection.getInstanceForTransport(transport);
        fido2AppletConnection.connectIfNecessary();
        fido2AppletConnection.setForceCtap1(fido2Config.isForceU2f());

        WebauthnSecurityKeyOperationFactory operationFactory =
                new WebauthnSecurityKeyOperationFactory(new PinProtocolV1(new PinAuthCryptoUtil()));
        return new Fido2SecurityKey(config, fido2AppletConnection, transport, new Fido2AsyncOperationManager(),
                operationFactory);
    }

    @Override
    protected boolean isRelevantTransport(Transport transport) {
        return transport.getTransportType() == TransportType.USB_CTAPHID
                // || transport.getTransportType() == TransportType.USB_CCID
                || transport.getTransportType() == TransportType.NFC;
    }

    @Override
    protected boolean isRelevantSecurityKey(SecurityKey securityKey) {
        return securityKey instanceof Fido2SecurityKey;
    }
}
