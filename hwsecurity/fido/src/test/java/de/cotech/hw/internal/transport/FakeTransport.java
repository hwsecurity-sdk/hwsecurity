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
import java.util.LinkedList;

import androidx.annotation.Nullable;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.SecurityKeyType;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.util.Hex;

import static org.junit.Assert.assertEquals;


@SuppressWarnings("WeakerAccess")
public class FakeTransport implements Transport {
    LinkedList<CommandApdu> expectCommands = new LinkedList<>();
    LinkedList<ResponseApdu> expectResponses = new LinkedList<>();
    LinkedList<IOException> expectExceptions = new LinkedList<>();
    boolean extendedLengthSupported = false;

    @Override
    public ResponseApdu transceive(CommandApdu data) throws IOException {
        CommandApdu expected = expectCommands.poll();
        assertEquals(expected, data);

        if (!expectExceptions.isEmpty()) {
            throw expectExceptions.poll();
        }

        return expectResponses.poll();
    }

    @Override
    public void release() {

    }

    @Override
    public boolean isConnected() {
        return true;
    }

    @Override
    public boolean isReleased() {
        return false;
    }

    @Override
    public boolean isPersistentConnectionAllowed() {
        return false;
    }

    @Override
    public void connect() throws IOException {

    }

    @Override
    public boolean ping() {
        return true;
    }

    @Override
    public TransportType getTransportType() {
        return TransportType.USB_CTAPHID;
    }

    @Nullable
    @Override
    public SecurityKeyType getSecurityKeyTypeIfAvailable() {
        return null;
    }

    @Override
    public boolean isExtendedLengthSupported() {
        return extendedLengthSupported;
    }

    public void setExtendedLengthSupported(boolean extendedLengthSupported) {
        this.extendedLengthSupported = extendedLengthSupported;
    }

    public void expect(String commandBytesHex, String responseBytesHex) throws IOException {
        expectCommands.add(CommandApdu.fromBytes(Hex.decodeHexOrFail(commandBytesHex)).withExtendedApduNe());
        expectResponses.add(ResponseApdu.fromBytes(Hex.decodeHexOrFail(responseBytesHex)));
    }

    public void expect(CommandApdu commandApdu, ResponseApdu responseApdu) {
        expectCommands.add(commandApdu);
        expectResponses.add(responseApdu);
    }

    public void expect(CommandApdu commandApdu, IOException exception) {
        expectCommands.add(commandApdu);
        expectExceptions.add(exception);
    }
}
