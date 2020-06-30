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

package de.cotech.hw.fido2.internal;


import java.io.IOException;

import de.cotech.hw.internal.transport.FakeTransport;
import org.junit.Assert;


@SuppressWarnings("WeakerAccess")
public class FakeFido2AppletConnection {
    public static final String GET_VERSION_COMMAND = "00030000";
    public static final String GET_VERSION_RESPONSE = "5532465f56329000";
    public static final String GET_INFO_COMMAND = "801000000104";
    public static final String GET_INFO_RESPONSE_PIN_NO = "00a60182665532465f5632684649444f5f325f3002816b686d61632d73656372657403506d44ba9bf6ec2e49b9300c8fe920cb7304a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b00681019000";
    public static final String GET_INFO_RESPONSE_PIN_YES ="00a60182665532465f5632684649444f5f325f3002816b686d61632d73656372657403506d44ba9bf6ec2e49b9300c8fe920cb7304a462726bf5627570f564706c6174f469636c69656e7450696ef5051904b00681019000";
    public Fido2AppletConnection connection;
    FakeTransport fakeTransport;

    FakeFido2AppletConnection(Fido2AppletConnection connection, FakeTransport fakeTransport) {
        this.connection = connection;
        this.fakeTransport = fakeTransport;
    }

    public static FakeFido2AppletConnection create(boolean hasClientPin) throws Exception {
        FakeTransport fakeTransport = new FakeTransport();
        Fido2AppletConnection connection = Fido2AppletConnection.getInstanceForTransport(fakeTransport);

        fakeTransport.expect(GET_VERSION_COMMAND, GET_VERSION_RESPONSE);
        fakeTransport.expect(GET_INFO_COMMAND, hasClientPin ? GET_INFO_RESPONSE_PIN_YES : GET_INFO_RESPONSE_PIN_NO);
        connection.connectIfNecessary();

        return new FakeFido2AppletConnection(connection, fakeTransport);
    }

    public void expect(String command, String reply) throws IOException {
        fakeTransport.expect(command, reply);
    }

    public void verify() {
        fakeTransport.verify();
    }
}
