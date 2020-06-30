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

package de.cotech.hw.raw;


import java.io.IOException;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.internal.transport.Transport;


/**
 * A shim Security Key that bears no semantics of its own, but allows the programmer
 * to dynamically connect other connection modes via
 * {@link RawSecurityKey#establishAppletConnection(SecurityKeyConnectionMode)}.
 * <p>
 * This SecurityKey is intended for advanced use cases. It should not be necessary for common
 * use cases that only work with one kind of applet.
 */
public class RawSecurityKey extends SecurityKey {
    private SecurityKey currentSecurityKey;

    RawSecurityKey(SecurityKeyManagerConfig config, Transport transport) {
        super(config, transport);
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    public Transport getTransport() {
        return transport;
    }

    /**
     * Establishes a connection to an applet through the provided {@link SecurityKeyConnectionMode}.
     * <p>
     * Note that the {@link RawSecurityKey} does not thoroughly manage the status of the currently
     * connected applet. A caller of this method must take care not to mix calls of different
     * applets.
     */
    @NonNull
    @WorkerThread
    public <T extends SecurityKey> T establishAppletConnection(@NonNull SecurityKeyConnectionMode<T> securityKeyConnectionMode)
            throws IOException {
        T securityKey = securityKeyConnectionMode.establishSecurityKeyConnection(config, transport);
        currentSecurityKey = securityKey;
        return securityKey;
    }

    public SecurityKey getCurrentSecurityKey() {
        return currentSecurityKey;
    }
}
