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

package de.cotech.hw.fido.internal;


import java.io.IOException;

import de.cotech.hw.internal.transport.FakeTransport;


@SuppressWarnings("WeakerAccess")
public class FakeU2fFidoAppletConnection {
    public static final String GET_VERSION_COMMAND = "00030000";
    public static final String GET_VERSION_RESPONSE = "5532465f56329000";
    public FidoU2fAppletConnection connection;
    FakeTransport fakeTransport;

    FakeU2fFidoAppletConnection(FidoU2fAppletConnection connection, FakeTransport fakeTransport) {
        this.connection = connection;
        this.fakeTransport = fakeTransport;
    }

    public static FakeU2fFidoAppletConnection create() throws Exception {
        FakeTransport fakeTransport = new FakeTransport();
        FidoU2fAppletConnection connection = FidoU2fAppletConnection.getInstanceForTransport(fakeTransport);

        fakeTransport.expect(GET_VERSION_COMMAND, GET_VERSION_RESPONSE);
        connection.connectIfNecessary();

        return new FakeU2fFidoAppletConnection(connection, fakeTransport);
    }

    public void expect(String command, String reply) throws IOException {
        fakeTransport.expect(command, reply);
    }
}
