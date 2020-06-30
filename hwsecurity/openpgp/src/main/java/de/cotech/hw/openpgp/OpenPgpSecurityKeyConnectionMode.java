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
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.util.HwTimber;

import java.io.IOException;


public class OpenPgpSecurityKeyConnectionMode extends SecurityKeyConnectionMode<OpenPgpSecurityKey> {
    private static OpenPgpSecurityKeyConnectionMode INSTANCE;

    public static void setDefaultConfig(OpenPgpSecurityKeyConnectionModeConfig config) {
        INSTANCE = new OpenPgpSecurityKeyConnectionMode(config);
    }

    public static OpenPgpSecurityKeyConnectionMode getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new OpenPgpSecurityKeyConnectionMode(OpenPgpSecurityKeyConnectionModeConfig.getDefaultConfig());
        }
        return INSTANCE;
    }

    public static OpenPgpSecurityKeyConnectionMode getInstance(OpenPgpSecurityKeyConnectionModeConfig config) {
        return new OpenPgpSecurityKeyConnectionMode(config);
    }

    private OpenPgpSecurityKeyConnectionMode(OpenPgpSecurityKeyConnectionModeConfig config) {
        this.config = config;
    }

    private final OpenPgpSecurityKeyConnectionModeConfig config;

    @Override
    @WorkerThread
    public OpenPgpSecurityKey establishSecurityKeyConnection(SecurityKeyManagerConfig securityKeyManagerConfig,
                                                             Transport transport) throws IOException {
        if (transport.getTransportType() == SecurityKeyInfo.TransportType.USB_CTAPHID) {
            HwTimber.d("USB CTAPHID is available but not supported by OPENPGP.");
            return null;
        }

        OpenPgpAppletConnection openPgpAppletConnection = OpenPgpAppletConnection.getInstanceForTransport(
                transport, config.getOpenPgpAidPrefixes());
        openPgpAppletConnection.connectIfNecessary();

        return new OpenPgpSecurityKey(securityKeyManagerConfig, transport, openPgpAppletConnection);
    }

    @Override
    protected boolean isRelevantTransport(Transport transport) {
        return transport.getTransportType() != SecurityKeyInfo.TransportType.USB_CTAPHID;
    }

    @Override
    protected boolean isRelevantSecurityKey(SecurityKey securityKey) {
        return securityKey instanceof OpenPgpSecurityKey;
    }
}
