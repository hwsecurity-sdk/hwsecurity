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


import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.LinkedList;

import android.annotation.TargetApi;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbRequest;
import android.os.Build.VERSION_CODES;

import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.stubbing.Answer;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@SuppressWarnings({ "WeakerAccess", "SameParameterValue" })
@TargetApi(VERSION_CODES.JELLY_BEAN_MR2)
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 24)
public class CtapHidTransportProtocolTest {
    static final int CHANNEL_ID = 12345678;
    static final byte[] DATA_IN = Hex.decodeHexOrFail("1a2b3d4e5f");
    static final byte[] DATA_OUT = Hex.decodeHexOrFail("5f4e3d2c1b");
    static final byte[] DATA_IN_LONG = new byte[200];
    static final byte[] DATA_OUT_LONG = new byte[199];

    UsbDeviceConnection usbConnection;
    UsbEndpoint usbIntIn;
    UsbEndpoint usbIntOut;

    LinkedList<UsbRequest> requestQueue;

    CtapHidTransportProtocol protocol;
    CtapHidFrameFactory frameFactory = new CtapHidFrameFactory();

    @Before
    public void setUp() {
        usbConnection = mock(UsbDeviceConnection.class);
        usbIntIn = mock(UsbEndpoint.class);
        usbIntOut = mock(UsbEndpoint.class);

        requestQueue = new LinkedList<>();

        protocol = new CtapHidTransportProtocol(usbConnection, usbIntIn, usbIntOut) {
            @Override
            UsbRequest newUsbRequest() {
                return requestQueue.poll();
            }
        };
    }

    @Test
    public void connect() throws Exception {
        expect(CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_INIT, nonce ->
                ByteBuffer
                        .allocate(17)
                        .order(ByteOrder.BIG_ENDIAN)
                        .put(nonce)
                        .putInt(CHANNEL_ID)
                        .put((byte) 2) // channelId
                        .put((byte) 7) // versionMajor
                        .put((byte) 1) // versionMinor
                        .put((byte) 3) // versionBuild
                        .put((byte) 1) // capability flags
                        .array());

        protocol.connect();

        assertEquals(CHANNEL_ID, protocol.getChannelId());
        verifyDialog();
    }

    @Test(expected = UsbTransportException.class)
    public void connect_badNonce() throws Exception {
        expect(CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_INIT, nonce -> {
            nonce[0] ^= (byte) 0x25;
            return ByteBuffer
                    .allocate(17)
                    .order(ByteOrder.BIG_ENDIAN)
                    .put(nonce)
                    .putInt(CHANNEL_ID)
                    .put((byte) 2) // channelId
                    .put((byte) 7) // versionMajor
                    .put((byte) 1) // versionMinor
                    .put((byte) 3) // versionBuild
                    .put((byte) 1) // capability flags
                    .array();
        });

        protocol.connect();
    }

    @Test(expected = UsbTransportException.class)
    public void connect_leadingGarbage() throws Exception {
        expect(CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_INIT,
                nonce -> Hex.decodeHexOrFail("0102030405060708"));
        expect(CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_INIT,
                nonce -> Hex.decodeHexOrFail("0807060504030201"));
        expect(CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_INIT, nonce ->
                ByteBuffer
                        .allocate(17)
                        .order(ByteOrder.BIG_ENDIAN)
                        .put(nonce)
                        .putInt(CHANNEL_ID)
                        .put((byte) 2) // channelId
                        .put((byte) 7) // versionMajor
                        .put((byte) 1) // versionMinor
                        .put((byte) 3) // versionBuild
                        .put((byte) 1) // capability flags
                        .array());

        protocol.connect();

        assertEquals(CHANNEL_ID, protocol.getChannelId());
        verifyDialog();
    }

    @Test
    public void transceive_short() throws Exception {
        connect();

        expect(CHANNEL_ID, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_MSG, data -> {
            assertArrayEquals(DATA_IN, data);
            return DATA_OUT;
        });

        byte[] response = protocol.transceive(DATA_IN);

        assertArrayEquals(DATA_OUT, response);
        verifyDialog();
    }

    @Test
    public void transceive_long() throws Exception {
        connect();

        expect(CHANNEL_ID, CHANNEL_ID, CtapHidFrameFactory.CTAPHID_MSG, data -> {
            assertArrayEquals(DATA_IN_LONG, data);
            return DATA_OUT_LONG;
        });

        byte[] response = protocol.transceive(DATA_IN_LONG);

        assertArrayEquals(DATA_OUT_LONG, response);
        verifyDialog();
    }

    private void verifyDialog() {
        assertTrue(requestQueue.isEmpty());
    }

    private void expect(int inputChannelId, int outputChannelId, byte cmdId, CtapCommunicationCallback callback) {
        RequestState state = new RequestState();

        UsbRequest usbRequestOut = mock(UsbRequest.class);
        when(usbRequestOut.initialize(usbConnection, usbIntOut)).thenReturn(true);
        when(usbRequestOut.queue(any(ByteBuffer.class), eq(CtapHidFrameFactory.CTAPHID_BUFFER_SIZE))).thenAnswer(
                (Answer<Boolean>) invocation -> {
                    state.inputAccumulator.write(invocation.<ByteBuffer>getArgument(0).array());
                    return true;
                });
        requestQueue.add(usbRequestOut);

        UsbRequest usbRequestIn = mock(UsbRequest.class);
        when(usbRequestIn.initialize(usbConnection, usbIntIn)).thenReturn(true);
        when(usbRequestIn.queue(any(ByteBuffer.class), eq(CtapHidFrameFactory.CTAPHID_BUFFER_SIZE))).thenAnswer(
                (Answer<Boolean>) invocation -> {
                    if (!state.inputFinished) {
                        state.inputFinished = true;
                        byte[] inputFrame = frameFactory.unwrapFrame(inputChannelId, cmdId, state.inputAccumulator.toByteArray());
                        byte[] responseBytes = callback.communicate(inputFrame);
                        state.output = frameFactory.wrapFrame(outputChannelId, cmdId, responseBytes);
                        state.inputAccumulator = null;
                        state.outputOffset = 0;
                    }
                    ByteBuffer buf = invocation.getArgument(0);
                    assertEquals(CtapHidFrameFactory.CTAPHID_BUFFER_SIZE, buf.capacity());
                    buf.clear();
                    buf.put(state.output, state.outputOffset, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);
                    state.outputOffset += CtapHidFrameFactory.CTAPHID_BUFFER_SIZE;
                    return true;
                });
        requestQueue.add(usbRequestIn);
    }

    static class RequestState {
        ByteArrayOutputStream inputAccumulator = new ByteArrayOutputStream();
        boolean inputFinished;
        public byte[] output;
        int outputOffset;
    }

    interface CtapCommunicationCallback {
        byte[] communicate(byte[] payload);
    }
}
