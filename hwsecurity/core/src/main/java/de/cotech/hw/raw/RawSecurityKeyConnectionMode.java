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


import java.util.Collections;
import java.util.List;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyConnectionMode;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;

/**
 * A connection mode that performs no initialization of its own, and instead allows the programmer
 * to dynamically connect to applets via {@link RawSecurityKey#establishAppletConnection(SecurityKeyConnectionMode)}.
 * <p>
 * This connection mode is intended for advanced use cases. It should not be necessary for common
 * use cases that only work with one kind of applet.
 */
public class RawSecurityKeyConnectionMode extends SecurityKeyConnectionMode<RawSecurityKey> {
    private final List<TransportType> allowedTransportTypes;

    public RawSecurityKeyConnectionMode() {
        this.allowedTransportTypes = null;
    }

    public RawSecurityKeyConnectionMode(List<TransportType> allowedTransportTypes) {
        this.allowedTransportTypes = Collections.unmodifiableList(allowedTransportTypes);
    }

    @Override
    public RawSecurityKey establishSecurityKeyConnection(SecurityKeyManagerConfig config, Transport transport) {
        return new RawSecurityKey(config, transport);
    }

    @Override
    protected boolean isRelevantTransport(Transport transport) {
        return allowedTransportTypes == null || allowedTransportTypes.contains(transport.getTransportType());
    }

    @Override
    protected boolean isRelevantSecurityKey(SecurityKey securityKey) {
        return true;
    }
}
