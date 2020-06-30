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

package de.cotech.hw.fido;


import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.fido.internal.async.FidoAsyncOperationManager;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;


public class FidoSecurityKeyConnectionMode extends SecurityKeyConnectionMode<FidoSecurityKey> {

    @Override
    public FidoSecurityKey establishSecurityKeyConnection(SecurityKeyManagerConfig config, Transport transport) throws IOException {
        if (!isRelevantTransport(transport)) {
            throw new IllegalArgumentException("Received incompatible transport!");
        }

        FidoU2fAppletConnection fidoU2fAppletConnection = FidoU2fAppletConnection.getInstanceForTransport(transport);
        fidoU2fAppletConnection.connectIfNecessary();

        return new FidoSecurityKey(config, fidoU2fAppletConnection, transport, new FidoAsyncOperationManager());
    }

    @Override
    protected boolean isRelevantTransport(Transport transport) {
        return transport.getTransportType() == TransportType.USB_CTAPHID
                // || transport.getTransportType() == TransportType.USB_CCID
                || transport.getTransportType() == TransportType.NFC;
    }

    @Override
    protected boolean isRelevantSecurityKey(SecurityKey securityKey) {
        return securityKey instanceof FidoSecurityKey;
    }
}
