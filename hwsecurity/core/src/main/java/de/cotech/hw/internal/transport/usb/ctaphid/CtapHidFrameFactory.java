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


import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import androidx.annotation.VisibleForTesting;
import de.cotech.hw.internal.transport.usb.UsbTransportException;

final class CtapHidFrameFactory {
    private static final byte TYPE_INIT = (byte) 0x80; // Initial frame identifier

    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_PING = (byte) (TYPE_INIT | 0x01); // Echo data through local processor only
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_MSG = (byte) (TYPE_INIT | 0x03); // Send CTAPHID message frame
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_LOCK = (byte) (TYPE_INIT | 0x04); // Send lock channel command
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_INIT = (byte) (TYPE_INIT | 0x06); // Channel initialization
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_WINK = (byte) (TYPE_INIT | 0x08); // Send device identification wink
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_CBOR = (byte) (TYPE_INIT | 0x10); // Send CTAPHID message frame
    @SuppressWarnings("unused") // public API
    static final byte CTAPHID_ERROR = (byte) (TYPE_INIT | 0x3f); // Error response
    @SuppressWarnings({ "WeakerAccess" }) // public API
    static final byte CTAPHID_KEEPALIVE = (byte) (TYPE_INIT | 0x3b); // Just a keepalive response

    static final int CTAPHID_BUFFER_SIZE = 64;
    static final int CTAPHID_CHANNEL_ID_BROADCAST = 0xffffffff;

    private static final int FRST_PKT_HDR_LEN = 7;
    private static final int CONT_PACKET_HEADER_LENGTH = 5;
    private static final int MAX_LENGTH_INIT_PACKET = CTAPHID_BUFFER_SIZE - FRST_PKT_HDR_LEN;
    private static final int MAX_LENGTH_CONT_PACKET = CTAPHID_BUFFER_SIZE - CONT_PACKET_HEADER_LENGTH;
    private static final int MAX_LENGTH_PAYLOAD = MAX_LENGTH_INIT_PACKET + 128 * MAX_LENGTH_CONT_PACKET;

    private static final int KEEPALIVE_TYPE_PROCESSING = 1;
    private static final int KEEPALIVE_TYPE_UPNEEDED = 2;

    /**
     * Generate HID packet(s) required to send the payload with the given command.
     *
     * @param channelId  channel identifier
     * @param cmdId      command identifier
     * @param payload    payload data
     * @return HID packets containing the payload data
     */
    byte[] wrapFrame(int channelId, byte cmdId, byte[] payload) throws UsbTransportException {
        try {
            return wrapFrameOrThrow(channelId, cmdId, payload);
        } catch (BufferUnderflowException | BufferOverflowException | IndexOutOfBoundsException e) {
            throw new UsbTransportException(e);
        }
    }

    private byte[] wrapFrameOrThrow(int channelId, byte cmdId, byte[] payload) {
        int packetsRequiredForPayload = calculatePacketCountForPayload(payload.length);
        ByteBuffer output = ByteBuffer.allocate(packetsRequiredForPayload * CTAPHID_BUFFER_SIZE).order(ByteOrder.BIG_ENDIAN);

        int offset = 0;
        int sequenceIdx = 0;

        offset += writeInitPacket(cmdId, channelId, payload, output);
        while (offset != payload.length) {
            offset += writeContPacket(sequenceIdx, channelId, payload, offset, output);
            sequenceIdx += 1;
        }
        return output.array();
    }

    /**
     *  typedef struct {
     *     uint32_t cid;  // Channel identifier
     * 	   uint8_t seq;   // Sequence number - b7 cleared
     * 	   uint8_t data[HID_RPT_SIZE - 5];	// Data payload
     * } CTAPHID_FRAME_CONT;
     */
    private int writeContPacket(int sequenceIdx, int channelId, byte[] payload, int offset,
            ByteBuffer output) {
        if ((sequenceIdx & TYPE_INIT) != 0) {
            throw new IllegalArgumentException(
                    "Invalid sequence identifier: 0x" + Integer.toHexString(sequenceIdx) + " (expected bit 7 to be unset)");
        }

        int blockSize = Math.min(MAX_LENGTH_CONT_PACKET, payload.length - offset);

        output.putInt(channelId);
        output.put((byte) (sequenceIdx & 0xff));
        output.put(payload, offset, blockSize);

        return blockSize;
    }

    /**
     *   typedef struct {
     *     uint32_t cid;   // Channel identifier
     * 	   uint8_t cmd;    // Command - b7 set
     * 	   uint8_t bcnth;  // Message byte count - high part
     * 	   uint8_t bcntl;  // Message byte count - low part
     * 	   uint8_t data[HID_RPT_SIZE - 7];	// Data payload
     * } CTAPHID_FRAME_INIT;
     */
    private int writeInitPacket(byte cmdId, int channelId, byte[] payload, ByteBuffer output) {
        if ((cmdId & TYPE_INIT) == 0) {
            throw new IllegalArgumentException(
                    "Invalid command: 0x" + Integer.toHexString(cmdId) + " (expected bit 7 to be set)");
        }

        int blockSize = Math.min(MAX_LENGTH_INIT_PACKET, payload.length);

        output.putInt(channelId);
        output.put(cmdId);
        output.putShort((short) payload.length);
        output.put(payload, 0, blockSize);

        return blockSize;
    }

    int findExpectedFramesFromInitPacketHeader(int expectedChannelId, ByteBuffer initPacket)
            throws UsbTransportException {
        try {
            initPacket.mark();
            FrameInitPacketHeader initPacketHeader = FrameInitPacketHeader.fromByteBuffer(initPacket);
            if (expectedChannelId != CTAPHID_CHANNEL_ID_BROADCAST && initPacketHeader.channelId != expectedChannelId) {
                throw new CtapHidChangedChannelException(expectedChannelId, initPacketHeader.channelId);
            }
            initPacket.reset();
            return calculatePacketCountForPayload(initPacketHeader.payloadLength);
        } catch (BufferUnderflowException e) {
            throw new UsbTransportException(e);
        }
    }

    KeepaliveType unwrapFrameAsKeepalivePacket(byte[] frameBytes) {
        ByteBuffer frame = ByteBuffer.wrap(frameBytes).order(ByteOrder.BIG_ENDIAN);
        FrameInitPacketHeader initPacket = FrameInitPacketHeader.fromByteBuffer(frame);
        if (initPacket.cmdId != CTAPHID_KEEPALIVE) {
            return null;
        }
        if (initPacket.payloadLength != 1) {
            return KeepaliveType.UNKNOWN;
        }
        switch (frame.get()) {
            case KEEPALIVE_TYPE_PROCESSING: return KeepaliveType.PROCESSING;
            case KEEPALIVE_TYPE_UPNEEDED: return KeepaliveType.UPNEEDED;
            default: return KeepaliveType.UNKNOWN;
        }
    }

    /**
     * Return null until we can completely parse a multi-packet response sans error.
     *
     *
     * @param expectedCmdId      expected command identifier
     * @param frameBytes       APDU
     * @return contents of response APDU
     * @throws UsbTransportException Thrown on error process the response.
     */
    byte[] unwrapFrame(int expectedChannelId, byte expectedCmdId, byte[] frameBytes) throws UsbTransportException {
        try {
            return unwrapFrameOrThrow(expectedChannelId, expectedCmdId, frameBytes);
        } catch (BufferUnderflowException | BufferOverflowException | IndexOutOfBoundsException e) {
            throw new UsbTransportException(e);
        }
    }

    private byte[] unwrapFrameOrThrow(int expectedChannelId, byte expectedCmdId, byte[] frameBytes)
            throws UsbTransportException {
        ByteBuffer frame = ByteBuffer.wrap(frameBytes).order(ByteOrder.BIG_ENDIAN);

        FrameInitPacketHeader initPacket = FrameInitPacketHeader.fromByteBuffer(frame);
        if (initPacket.cmdId != expectedCmdId) {
            throw new UsbTransportException("Command mismatch = " + (initPacket.cmdId & 0xff) + " Tag = " + (expectedCmdId & 0xff));
        }

        if (expectedChannelId != CTAPHID_CHANNEL_ID_BROADCAST && initPacket.channelId != expectedChannelId) {
            throw new CtapHidChangedChannelException(expectedChannelId, initPacket.channelId);
        }

        // check we don't have less data than claimed
        int expectedBufferLength = calculatePacketCountForPayload(initPacket.payloadLength) * CTAPHID_BUFFER_SIZE;

        if (frame.capacity() != expectedBufferLength) {
            throw new UsbTransportException(
                    "Payload not finished (" + frame.capacity() + "/" + expectedBufferLength + " bytes).");
        }

        byte[] payload = new byte[initPacket.payloadLength];

        int offset = 0;
        int sequenceIdx = 0;

        offset += readInitPacketPayload(frame, payload);
        while (offset != payload.length) {
            offset += readContPacket(initPacket.channelId, frame, payload, offset, sequenceIdx);
            sequenceIdx += 1;
        }

        return payload;
    }

    private int readInitPacketPayload(ByteBuffer frame, byte[] payload) {
        int packetPayloadLength = Math.min(payload.length, MAX_LENGTH_INIT_PACKET);
        frame.get(payload, 0, packetPayloadLength);
        return packetPayloadLength;
    }

    private int readContPacket(int expectedChannelId, ByteBuffer frame, byte[] payload, int offset, int sequenceCounter)
            throws UsbTransportException {
        int channelId = frame.getInt();
        if (channelId != expectedChannelId) {
            throw new CtapHidChangedChannelException(expectedChannelId, channelId);
        }

        byte sequenceId = frame.get();
        if (sequenceId != sequenceCounter) {
            throw new UsbTransportException(
                    "Out of sequence packet. Sequence " + sequenceId + "; expected " + sequenceCounter);
        }
        int packetPayloadLength = Math.min(payload.length - offset, MAX_LENGTH_CONT_PACKET);
        frame.get(payload, offset, packetPayloadLength);
        return packetPayloadLength;
    }

    @VisibleForTesting
    int calculatePacketCountForPayload(int length) {
        if (length > MAX_LENGTH_PAYLOAD) {
            throw new IllegalArgumentException("Payload too large, CtapHid maximum is 7906 bytes!");
        }

        int lengthAfterFirstPacket = length - MAX_LENGTH_INIT_PACKET;
        return 1 + (lengthAfterFirstPacket + MAX_LENGTH_CONT_PACKET - 1) / MAX_LENGTH_CONT_PACKET;
    }


    public enum KeepaliveType {
        PROCESSING, UPNEEDED, UNKNOWN
    }

    private static class FrameInitPacketHeader {
        int channelId;
        byte cmdId;
        int payloadLength;

        FrameInitPacketHeader(int channelId, byte cmdId, int payloadLength) {
            this.channelId = channelId;
            this.cmdId = cmdId;
            this.payloadLength = payloadLength;
        }

        static FrameInitPacketHeader fromByteBuffer(ByteBuffer frame) {
            int channelId = frame.getInt();
            byte cmd = frame.get();
            int payloadLength = frame.getShort();
            return new FrameInitPacketHeader(channelId, cmd, payloadLength);
        }
    }
}