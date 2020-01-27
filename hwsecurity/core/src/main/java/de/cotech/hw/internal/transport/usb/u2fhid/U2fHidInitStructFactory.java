/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.internal.transport.usb.u2fhid;


import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Random;

import com.google.auto.value.AutoValue;
import de.cotech.hw.internal.transport.usb.UsbTransportException;


@SuppressWarnings("unused") // public API
class U2fHidInitStructFactory {
    private static final int INIT_NONCE_SIZE = 8;
    private final Random random;

    U2fHidInitStructFactory(Random random) {
        this.random = random;
    }

    /** Generate an initialization request.
     *
     *  typedef struct {
     *      uint8_t nonce[INIT_NONCE_SIZE];	// Client application nonce
     *  } U2FHID_INIT_REQ;
     *
     */
    byte[] createInitRequest() {
        byte[] nonce = new byte[U2fHidInitStructFactory.INIT_NONCE_SIZE];
        random.nextBytes(nonce);
        return nonce;
    }

    /** Check and parse an initialization response.
     *
     *   typedef struct
     *   {
     *     uint8_t nonce[INIT_NONCE_SIZE];	// Client application nonce
     *     uint32_t cid;		// Channel identifier
     *     uint8_t versionInterface;	// Interface version
     *     uint8_t versionMajor;	// Major version number
     *     uint8_t versionMinor;	// Minor version number
     *     uint8_t versionBuild;	// Build version number
     *     uint8_t capFlags;		// Capabilities flags
     * } U2FHID_INIT_RESP;
     */
    U2fHidInitResponse parseInitResponse(byte[] responseBytes, byte[] requestBytes) throws UsbTransportException {
        try {
            return getU2fHidInitResponseOrThrow(responseBytes, requestBytes);
        } catch (BufferOverflowException | BufferUnderflowException e) {
            throw new UsbTransportException(e);
        }
    }

    private U2fHidInitResponse getU2fHidInitResponseOrThrow(byte[] responseBytes, byte[] requestBytes)
            throws UsbTransportException {
        ByteBuffer response = ByteBuffer.wrap(responseBytes);
        ByteBuffer request = ByteBuffer.wrap(requestBytes);

        response.limit(INIT_NONCE_SIZE);
        if (!request.equals(response)) {
            throw new UsbTransportException("Invalid channel initialization.");
        }
        response.clear();
        response.position(INIT_NONCE_SIZE);

        return U2fHidInitResponse.readFromByteBuffer(response);
    }

    @AutoValue
    static abstract class U2fHidInitResponse {
        private static final byte CAPFLAG_WINK = 1;
        private static final byte CAPFLAG_LOCK = 2;

        abstract int channelId();
        abstract byte versionInterface();
        abstract byte versionMajor();
        abstract byte versionMinor();
        abstract byte versionBuild();
        abstract byte capabilityFlags();

        static U2fHidInitResponse readFromByteBuffer(ByteBuffer buf) {
            int channelId = buf.getInt();
            byte versionInterface = buf.get();
            byte versionMajor = buf.get();
            byte versionMinor = buf.get();
            byte versionBuild = buf.get();
            byte capabilityFlags = buf.get();

            return new AutoValue_U2fHidInitStructFactory_U2fHidInitResponse(
                    channelId, versionInterface, versionMajor, versionMinor, versionBuild, capabilityFlags
            );
        }

        boolean supportsWink() {
            return (capabilityFlags() & CAPFLAG_WINK) != 0;
        }

        boolean supportsLock() {
            return (capabilityFlags() & CAPFLAG_LOCK) != 0;
        }
    }

}
