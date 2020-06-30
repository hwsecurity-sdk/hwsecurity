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


import java.io.IOException;

import androidx.annotation.AnyThread;
import androidx.annotation.WorkerThread;

import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;


/**
 * An abstract connected Security Key.
 *
 * Concrete instances of this class, such as FidoSecurityKey, PivSecurityKey, or OpenPgpSecurityKey,
 * offer methods to interact with the connected Security Key and applet.
 *
 * @see SecurityKeyCallback
 * @see SecurityKeyManager#registerCallback
 */
@SuppressWarnings({ "WeakerAccess", "unused" }) // public API
public abstract class SecurityKey {
    protected final SecurityKeyManagerConfig config;
    protected final Transport transport;

    public SecurityKey(SecurityKeyManagerConfig config, Transport transport) {
        this.config = config;
        this.transport = transport;
    }

    /**
     * This method checks if communication with the security key is still available by sending a no-op ping command.
     * <p>
     * This is useful especially for security keys connected via NFC, since the connection status as tracked by the
     * operating system sometimes has a delay of up to two seconds.
     * <p>
     * This method directly performs IO with the security token, and should therefore not be called on the UI thread.
     */
    @WorkerThread
    public void checkConnectionOrThrow() throws IOException {
        if (!transport.ping()) {
            throw new IOException("Transport no longer connected!");
        }
    }

    /**
     * @return true if the underlying transport is NFC.
     */
    @AnyThread
    public boolean isTransportNfc() {
        return transport.getTransportType() == TransportType.NFC;
    }

    /**
     * @return true if the underlying transport is USB.
     */
    @AnyThread
    public boolean isTransportUsb() {
        return transport.getTransportType() == TransportType.USB_CCID || transport.getTransportType() == TransportType.USB_CTAPHID;
    }

    /**
     * @return true if the underlying transport is persistently connected.
     */
    @AnyThread
    public boolean isPersistentlyConnected() {
        return transport.isPersistentConnectionAllowed();
    }

    /**
     * Releases the Security Key as well as the underlying transport.
     */
    public void release() {
        transport.release();
    }
}
