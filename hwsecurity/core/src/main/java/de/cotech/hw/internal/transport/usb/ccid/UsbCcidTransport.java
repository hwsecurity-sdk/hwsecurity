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

package de.cotech.hw.internal.transport.usb.ccid;


import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.util.Pair;

import java.io.IOException;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.SecurityKeyType;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.internal.transport.usb.UsbSecurityKeyTypes;
import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.internal.transport.usb.UsbUtils;
import de.cotech.hw.util.HwTimber;


/**
 * Based on USB CCID Specification rev. 1.1
 * http://www.usb.org/developers/docs/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf
 * Implements small subset of these features
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbCcidTransport implements Transport {

    private final UsbManager usbManager;
    private final UsbDevice usbDevice;
    private final UsbDeviceConnection usbConnection;
    private final UsbInterface usbInterface;
    private boolean enableDebugLogging;
    private CcidTransportProtocol ccidTransportProtocol;

    private boolean released = false;
    private TransportReleasedCallback transportReleasedCallback;

    public static UsbCcidTransport createUsbTransport(UsbManager usbManager, UsbDevice usbDevice,
            UsbDeviceConnection usbConnection,
            UsbInterface usbInterface, boolean enableDebugLogging) {
        return new UsbCcidTransport(usbManager, usbDevice, usbConnection, usbInterface, enableDebugLogging);
    }

    private UsbCcidTransport(UsbManager usbManager, UsbDevice usbDevice,
            UsbDeviceConnection usbConnection, UsbInterface usbInterface,
            boolean enableDebugLogging) {
        this.usbManager = usbManager;
        this.usbDevice = usbDevice;
        this.usbConnection = usbConnection;
        this.usbInterface = usbInterface;
        this.enableDebugLogging = enableDebugLogging;
    }

    /**
     * Check if device is was connected to and still is connected
     *
     * @return true if device is connected
     */
    @Override
    public boolean isConnected() {
        return ccidTransportProtocol != null && !released;
    }

    @Override
    public boolean isReleased() {
        return released;
    }

    @Override
    public void setTransportReleaseCallback(TransportReleasedCallback callback) {
        this.transportReleasedCallback = callback;
    }

    @Override
    public boolean isExtendedLengthSupported() {
        return true;
    }

    /**
     * Check if Transport supports persistent connections e.g connections which can
     * handle multiple operations in one session
     *
     * @return true if transport supports persistent connections
     */
    @Override
    public boolean isPersistentConnectionAllowed() {
        return true;
    }

    /**
     * Connect to USB_CCID device
     */
    @Override
    public void connect() throws IOException {
        Pair<UsbEndpoint, UsbEndpoint> ioEndpoints = UsbUtils.getIoEndpoints(
                usbInterface, UsbConstants.USB_ENDPOINT_XFER_BULK);
        UsbEndpoint usbBulkIn = ioEndpoints.first;
        UsbEndpoint usbBulkOut = ioEndpoints.second;

        if (usbBulkIn == null || usbBulkOut == null) {
            throw new UsbTransportException("USB_CCID error: invalid class 11 interface");
        }

        CcidDescriptor ccidDescriptor = CcidDescriptor.fromRawDescriptors(usbConnection.getRawDescriptors());
        HwTimber.d("CCID Descriptor: %s", ccidDescriptor);
        CcidTransceiver transceiver = new CcidTransceiver(usbConnection, usbBulkIn, usbBulkOut, ccidDescriptor);

        CcidTransportProtocol ccidTransportProtocol = ccidDescriptor.getSuitableTransportProtocol();
        ccidTransportProtocol.connect(transceiver);
        this.ccidTransportProtocol = ccidTransportProtocol;
    }

    /**
     * Transmit and receive data
     *
     * @param commandApdu data to transmit
     * @return received data
     */
    @Override
    public ResponseApdu transceive(CommandApdu commandApdu) throws IOException {
        if (released) {
            throw new SecurityKeyDisconnectedException();
        }
        byte[] rawCommand = commandApdu.toBytes();
        if (enableDebugLogging) {
            HwTimber.d("USB_CCID out: %s", commandApdu);
        }

        try {
            byte[] rawResponse = ccidTransportProtocol.transceive(rawCommand);

            ResponseApdu responseApdu = ResponseApdu.fromBytes(rawResponse);
            if (enableDebugLogging) {
                HwTimber.d("USB_CCID  in: %s", responseApdu);
            }

            return responseApdu;
        } catch (UsbTransportException e) {
            if (!UsbUtils.isDeviceStillConnected(usbManager, usbDevice)) {
                release();
                throw new SecurityKeyDisconnectedException(e);
            }
            throw e;
        }
    }

    @Override
    public void release() {
        if (!released) {
            HwTimber.d("USB_CCID transport disconnected");
            this.released = true;
            usbConnection.releaseInterface(usbInterface);
            if (transportReleasedCallback != null) {
                transportReleasedCallback.onTransportReleased();
            }
        }
    }

    @Override
    public TransportType getTransportType() {
        return TransportType.USB_CCID;
    }

    @Override
    public boolean ping() {
        // TODO actually ping?
        return !released;
    }

    @Nullable
    @Override
    public SecurityKeyType getSecurityKeyTypeIfAvailable() {
        return UsbSecurityKeyTypes
                .getSecurityKeyTypeFromUsbDeviceInfo(usbDevice.getVendorId(), usbDevice.getProductId(), usbConnection.getSerial());
    }
}
