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

package de.cotech.hw.internal.transport.usb.ctaphid;


import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;


@SuppressWarnings("WeakerAccess")
public class CtapHidFrameFactoryTest {
    // message max length = 64 - 7 + 128 * (64 - 5) = 7609 bytes
    static final int CTAPHID_MAX_SIZE = 7609;
    static final int CHANNEL_ID = 12345678;

    static final byte[] MESSAGE_SHORT = Hex.decodeHexOrFail("1a2b3d4f5a6b7c");
    static final byte[] MESSAGE_LONG = repeat(MESSAGE_SHORT, 128);

    CtapHidFrameFactory factory = new CtapHidFrameFactory();

    @Test
    public void wrapUnwrap_short() throws Exception {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        byte[] unwrappedCommand = factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);

        assertEquals(CtapHidFrameFactory.CTAPHID_PING, wrappedCommand[4]);
        assertArrayEquals(MESSAGE_SHORT, unwrappedCommand);
    }

    @Test
    public void wrapUnwrap_variableShort() throws Exception {
        for (int i = 0; i < 300; i++) {
            wrapUnwrap_variableLength(i);
        }
    }

    public void wrapUnwrap_variableLength(int len) throws Exception {
        byte[] payload = new byte[len];
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, payload);
        byte[] unwrappedCommand = factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);

        assertEquals(CtapHidFrameFactory.CTAPHID_PING, wrappedCommand[4]);
        assertArrayEquals(payload, unwrappedCommand);
    }

    @Test
    public void packetNumber() {
        assertEquals(1, factory.calculatePacketCountForPayload(0));
        assertEquals(1, factory.calculatePacketCountForPayload(5));
        assertEquals(1, factory.calculatePacketCountForPayload(57));
        assertEquals(2, factory.calculatePacketCountForPayload(58));
        assertEquals(2, factory.calculatePacketCountForPayload(115));
        assertEquals(2, factory.calculatePacketCountForPayload(116));
        assertEquals(3, factory.calculatePacketCountForPayload(117));
        assertEquals(3, factory.calculatePacketCountForPayload(175));
        assertEquals(4, factory.calculatePacketCountForPayload(176));
    }

    @Test
    public void wrapUnwrap_long() throws Exception {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_LONG);
        byte[] unwrappedCommand = factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);

        assertEquals(CtapHidFrameFactory.CTAPHID_PING, wrappedCommand[4]);
        assertArrayEquals(MESSAGE_LONG, unwrappedCommand);
    }

    @Test
    public void wrapUnwrap_max() throws Exception {
        byte[] MESSAGE_MAX = new byte[CTAPHID_MAX_SIZE];

        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_MAX);
        byte[] unwrappedCommand = factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);

        assertEquals(CtapHidFrameFactory.CTAPHID_PING, wrappedCommand[4]);
        assertArrayEquals(MESSAGE_MAX, unwrappedCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_badExpectedChannel() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        factory.unwrapFrame(CHANNEL_ID + 1, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_badExpectedCommand() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_MSG, wrappedCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_truncated() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        byte[] truncatedCommand = Arrays.copyOf(wrappedCommand, wrappedCommand.length - 1);

        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, truncatedCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_missingPacket() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_LONG);
        byte[] truncatedCommand = Arrays.copyOf(wrappedCommand, wrappedCommand.length - CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);

        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, truncatedCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_trailing() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        byte[] trailingDataCommand = Arrays.append(wrappedCommand, (byte) 0x50);

        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, trailingDataCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void wrapUnwrap_incorrectLength() throws UsbTransportException {
        byte[] wrappedCommand = factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, MESSAGE_SHORT);
        byte[] incorrectLengthCommand = Arrays.clone(wrappedCommand);
        incorrectLengthCommand[5] += 1;

        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, wrappedCommand);
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, incorrectLengthCommand);
    }

    @Test(expected = UsbTransportException.class)
    public void unwrap_empty() throws UsbTransportException {
        factory.unwrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void wrap_maxPlusOne() throws Exception {
        byte[] oversizedMessage = new byte[CTAPHID_MAX_SIZE + 1];
        factory.wrapFrame(CHANNEL_ID, CtapHidFrameFactory.CTAPHID_PING, oversizedMessage);
    }

    @Test(expected = IllegalArgumentException.class)
    public void wrap_withBadCommand_shouldCrash() throws UsbTransportException {
        factory.wrapFrame(CHANNEL_ID, (byte) ((5+1<<7) & 0xff), MESSAGE_SHORT);
    }

    public static byte[] repeat(byte[] array, int times) {
        byte[] result = new byte[array.length * times];
        for (int i = 0; i < times; i++) {
            System.arraycopy(array, 0, result,i*array.length, array.length);
        }
        return result;
    }
}