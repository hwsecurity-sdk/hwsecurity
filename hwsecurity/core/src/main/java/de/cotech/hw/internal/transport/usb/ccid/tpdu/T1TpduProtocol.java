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

package de.cotech.hw.internal.transport.usb.ccid.tpdu;


import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.transport.usb.ccid.CcidTransceiver;
import de.cotech.hw.internal.transport.usb.ccid.CcidTransceiver.CcidDataBlock;
import de.cotech.hw.internal.transport.usb.ccid.CcidTransportProtocol;
import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HwTimber;


/* T=1 Protocol, see http://www.icedev.se/proxmark3/docs/ISO-7816.pdf, Part 11 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class T1TpduProtocol implements CcidTransportProtocol {
    private final static int MAX_FRAME_LEN = 254;

    private static final byte PPS_PPPSS = (byte) 0xFF;
    private static final byte PPS_PPS0_T1 = 1;
    private static final byte PPS_PCK = (byte) (PPS_PPPSS ^ PPS_PPS0_T1);

    private CcidTransceiver ccidTransceiver;
    private T1TpduBlockFactory blockFactory;

    private byte sequenceCounter = 0;


    public void connect(@NonNull CcidTransceiver ccidTransceiver) throws UsbTransportException {
        if (this.ccidTransceiver != null) {
            throw new IllegalStateException("Protocol already connected!");
        }
        this.ccidTransceiver = ccidTransceiver;

        this.ccidTransceiver.iccPowerOn();

        // TODO: set checksum from atr
        blockFactory = new T1TpduBlockFactory(BlockChecksumAlgorithm.LRC);

        boolean skipPpsExchange = ccidTransceiver.hasAutomaticPps();
        if (!skipPpsExchange) {
            performPpsExchange();
        }
    }

    private void performPpsExchange() throws UsbTransportException {
        // Perform PPS, see ISO-7816, Part 9
        byte[] pps = { PPS_PPPSS, PPS_PPS0_T1, PPS_PCK };

        CcidDataBlock response = ccidTransceiver.sendXfrBlock(pps);

        if (!Arrays.areEqual(pps, response.getData())) {
            throw new UsbTransportException("Protocol and parameters (PPS) negotiation failed!");
        }
    }

    public byte[] transceive(@NonNull byte[] apdu) throws UsbTransportException {
        if (this.ccidTransceiver == null) {
            throw new IllegalStateException("Protocol not connected!");
        }

        if (apdu.length == 0) {
            throw new UsbTransportException("Cant transcive zero-length apdu(tpdu)");
        }

        IBlock responseBlock = sendChainedData(apdu);
        return receiveChainedResponse(responseBlock);
    }

    private IBlock sendChainedData(@NonNull byte[] apdu) throws UsbTransportException {
        int sentLength = 0;
        while (sentLength < apdu.length) {
            boolean hasMore = sentLength + MAX_FRAME_LEN < apdu.length;
            int len = Math.min(MAX_FRAME_LEN, apdu.length - sentLength);

            Block sendBlock = blockFactory.newIBlock(sequenceCounter++, hasMore, apdu, sentLength, len);
            CcidDataBlock response = ccidTransceiver.sendXfrBlock(sendBlock.getRawData());
            Block responseBlock = blockFactory.fromBytes(response.getData());

            sentLength += len;

            if (responseBlock instanceof SBlock) {
                HwTimber.d("S-Block received %s", responseBlock);
                // just ignore
            } else if (responseBlock instanceof RBlock) {
                HwTimber.d("R-Block received %s", responseBlock);
                if (((RBlock) responseBlock).getError() != RBlock.RError.NO_ERROR) {
                    throw new UsbTransportException("R-Block reports error " + ((RBlock) responseBlock).getError());
                }
            } else {  // I block
                if (sentLength != apdu.length) {
                    throw new UsbTransportException("T1 frame response underflow");
                }
                return (IBlock) responseBlock;
            }
        }

        throw new UsbTransportException("Invalid tpdu sequence state");
    }

    private byte[] receiveChainedResponse(IBlock responseIBlock) throws UsbTransportException {
        byte[] responseApdu = responseIBlock.getApdu();

        while (responseIBlock.getChaining()) {
            byte receivedSeqNum = responseIBlock.getSequence();

            Block ackBlock = blockFactory.createAckRBlock(receivedSeqNum);
            CcidDataBlock response = ccidTransceiver.sendXfrBlock(ackBlock.getRawData());
            Block responseBlock = blockFactory.fromBytes(response.getData());

            if (!(responseBlock instanceof IBlock)) {
                HwTimber.e("Invalid response block received %s", responseBlock);
                throw new UsbTransportException("Response: invalid state - invalid block received");
            }

            responseIBlock = (IBlock) responseBlock;
            responseApdu = Arrays.concatenate(responseApdu, responseBlock.getApdu());
        }

        return responseApdu;
    }
}
