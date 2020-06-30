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

package de.cotech.hw.internal.transport;


import java.io.IOException;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;


/**
 * Abstraction for transmitting APDU commands
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public interface Transport {
    /**
     * Transmit and receive data
     * @param data data to transmit
     * @return received data
     * @throws IOException
     */
    ResponseApdu transceive(CommandApdu data) throws IOException;

    /**
     * Disconnect and release connection
     */
    void release();

    /**
     * Check if device is was connected to and still is connected
     * @return connection status
     */
    boolean isConnected();

    boolean isReleased();

    /**
     * Check if Transport supports persistent connections e.g connections which can
     * handle multiple operations in one session
     * @return true if transport supports persistent connections
     */
    boolean isPersistentConnectionAllowed();

    /**
     * Returns true if this transport supports extended length APDUs.
     */
    boolean isExtendedLengthSupported();

    /**
     * Connect to device
     * @throws IOException
     */
    void connect() throws IOException;

    boolean ping();

    TransportType getTransportType();
    @Nullable
    SecurityKeyInfo.SecurityKeyType getSecurityKeyTypeIfAvailable();

    @RestrictTo(Scope.LIBRARY_GROUP)
    default void setTransportReleaseCallback(TransportReleasedCallback callback) {
        throw new UnsupportedOperationException();
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    interface TransportReleasedCallback {
        @WorkerThread
        void onTransportReleased();
    }
}
