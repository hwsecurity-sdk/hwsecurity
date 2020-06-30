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


import de.cotech.hw.exceptions.ClaNotSupportedException;
import de.cotech.hw.exceptions.InsNotSupportedException;
import de.cotech.hw.exceptions.WrongDataException;
import de.cotech.hw.exceptions.WrongRequestLengthException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.iso7816.ResponseApduUtils;
import de.cotech.hw.internal.transport.FakeTransport;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;


@SuppressWarnings("WeakerAccess")
public class FidoU2fAppletConnectionTest {
    static final CommandApdu PING_APDU = CommandApdu.create(0x00, 0xc0, 0x00, 0x00);
    static final CommandApdu PING_APDU_SHORT = CommandApdu.create(0x00, 0xc0, 0x00, 0x00).withShortApduNe();
    static final CommandApdu PING_APDU_EXTENDED = CommandApdu.create(0x00, 0xc0, 0x00, 0x00).withExtendedApduNe();

    FidoU2fAppletConnection connection;
    FakeTransport transport;

    @Before
    public void setup() {
        transport = new FakeTransport();
        connection = FidoU2fAppletConnection.getInstanceForTransport(transport);
    }

    @Test
    public void communicate_ping() throws Exception {
        transport.expect(PING_APDU_EXTENDED, ResponseApdu.fromBytes(Hex.decodeHexOrFail("9000")));
        connection.communicateOrThrow(PING_APDU);
    }

    @Test(expected = WrongRequestLengthException.class)
    public void communicateOrThrow_wrongLength() throws Exception {
        // On wrong length, we try again with short APDU encoding
        transport.expect(PING_APDU_EXTENDED, ResponseApduUtils.createError(0x6700));
        transport.expect(PING_APDU_SHORT, ResponseApduUtils.createError(0x6700));
        connection.communicateOrThrow(PING_APDU);
    }

    @Test(expected = WrongDataException.class)
    public void communicateOrThrow_wrongData() throws Exception {
        transport.expect(PING_APDU_EXTENDED, ResponseApduUtils.createError(0x6A80));
        connection.communicateOrThrow(PING_APDU);
    }

    @Test(expected = ClaNotSupportedException.class)
    public void communicateOrThrow_claNotSupported() throws Exception {
        transport.expect(PING_APDU_EXTENDED, ResponseApduUtils.createError(0x6E00));
        connection.communicateOrThrow(PING_APDU);
    }

    @Test(expected = InsNotSupportedException.class)
    public void communicateOrThrow_insNotSupported() throws Exception {
        transport.expect(PING_APDU_EXTENDED, ResponseApduUtils.createError(0x6D00));
        connection.communicateOrThrow(PING_APDU);
    }
}