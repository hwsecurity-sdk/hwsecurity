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


import java.io.IOException;
import java.util.Collections;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.piv.internal.PivAppletConnection;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


public class PivSecurityKeyConnectionMode extends SecurityKeyConnectionMode<PivSecurityKey> {
    private static final byte[] AID_PREFIX_PIV = Hex.decodeHexOrFail("A000000308");

    @Override
    public PivSecurityKey establishSecurityKeyConnection(SecurityKeyManagerConfig config, Transport transport) throws IOException {
        if (transport.getTransportType() == SecurityKeyInfo.TransportType.USB_CTAPHID) {
            HwTimber.d("USB CTAPHID is available but not supported by PIV.");
            return null;
        }

        PivAppletConnection pivAppletConnection = PivAppletConnection.getInstanceForTransport(
                transport, Collections.singletonList(AID_PREFIX_PIV));
        pivAppletConnection.connectIfNecessary();

        return new PivSecurityKey(config, transport, pivAppletConnection);
    }

    @Override
    protected boolean isRelevantTransport(Transport transport) {
        return transport.getTransportType() == TransportType.NFC ||
                transport.getTransportType() == TransportType.USB_CCID;
    }

    @Override
    protected boolean isRelevantSecurityKey(SecurityKey securityKey) {
        return securityKey instanceof PivSecurityKey;
    }
}
