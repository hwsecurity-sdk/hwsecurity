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


import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.SystemClock;
import android.util.Pair;

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
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


/**
 * USB CTAPHID
 * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbCtapHidTransport implements Transport {
    private static final int FIDO2_CLA_PROPRIETARY = 0x80;
    private static final int FIDO2_INS = 0x10;
    private static final int FIDO2_P1 = 0x00;
    private static final int FIDO2_P2 = 0x00;

    private static final List<String> HID_REPORT_FIDO_PREFIXES = Arrays.asList("06d0f10901", "06d0f10a0100");

    private final UsbManager usbManager;
    private final UsbDevice usbDevice;
    private final UsbDeviceConnection usbConnection;
    private final UsbInterface usbInterface;
    private boolean enableDebugLogging;
    private CtapHidTransportProtocol ctapHidTransportProtocol;

    private boolean released = false;
    private TransportReleasedCallback transportReleasedCallback;

    public static UsbCtapHidTransport createUsbTransport(UsbManager usbManager, UsbDevice usbDevice,
                                                         UsbDeviceConnection usbConnection,
                                                         UsbInterface usbInterface, boolean enableDebugLogging) {
        return new UsbCtapHidTransport(usbManager, usbDevice, usbConnection, usbInterface, enableDebugLogging);
    }

    private UsbCtapHidTransport(UsbManager usbManager, UsbDevice usbDevice,
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
        return ctapHidTransportProtocol != null && !released;
    }

    @Override
    public boolean isReleased() {
        return released;
    }

    @Override
    public void setTransportReleaseCallback(TransportReleasedCallback callback) {
        this.transportReleasedCallback = callback;
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
     * Connect to OTG device
     */
    @Override
    public void connect() throws IOException {
        if (ctapHidTransportProtocol != null) {
            throw new IllegalStateException("Already connected!");
        }

        Pair<UsbEndpoint, UsbEndpoint> ioEndpoints = UsbUtils.getIoEndpoints(
                usbInterface, UsbConstants.USB_ENDPOINT_XFER_INT);
        UsbEndpoint usbIntIn = ioEndpoints.first;
        UsbEndpoint usbIntOut = ioEndpoints.second;

        if (usbIntIn == null || usbIntOut == null) {
            throw new UsbTransportException("CTAPHID error: invalid class 3 interface");
        }

        checkHidReportPrefix();

        CtapHidTransportProtocol ctapHidTransportProtocol =
                new CtapHidTransportProtocol(usbConnection, usbIntIn, usbIntOut);
        ctapHidTransportProtocol.connect();
        this.ctapHidTransportProtocol = ctapHidTransportProtocol;
    }

    private void checkHidReportPrefix() throws IOException {
        byte[] hidReportDescriptor = UsbUtils.requestHidReportDescriptor(usbConnection, usbInterface.getId());
        String hidReportDescriptorHex = Hex.encodeHexString(hidReportDescriptor);
        for (String prefix : HID_REPORT_FIDO_PREFIXES) {
            if (hidReportDescriptorHex.startsWith(prefix)) {
                return;
            }
        }
        throw new IOException("HID descriptor prefix didn't match expected FIDO UsagePage and Usage!");
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

        try {
            return transceiveInternal(commandApdu);
        } catch (UsbTransportException e) {
            if (!UsbUtils.isDeviceStillConnected(usbManager, usbDevice)) {
                release();
                throw new SecurityKeyDisconnectedException(e);
            }
            throw e;
        }
    }

    private ResponseApdu transceiveInternal(CommandApdu commandApdu) throws IOException {
        // "For the U2FHID protocol, all raw U2F messages are encoded using extended length APDU encoding."
        // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html
        CommandApdu extendedCommandApdu = commandApdu.forceExtendedApduNe();

        if (enableDebugLogging) {
            HwTimber.d("CTAPHID out: %s", extendedCommandApdu);
        }

        long startRealtime = SystemClock.elapsedRealtime();
        ResponseApdu responseApdu;
        if (isCtap2Apdu(commandApdu)) {
            HwTimber.d("Using CTAP2 CBOR");
            byte[] rawResponse = ctapHidTransportProtocol.transceiveCbor(extendedCommandApdu.getData());
            responseApdu = ResponseApdu.create(0x9000, rawResponse);
        } else {
            byte[] rawResponse = ctapHidTransportProtocol.transceive(extendedCommandApdu.toBytes());
            responseApdu = ResponseApdu.fromBytes(rawResponse);
        }

        if (enableDebugLogging) {
            long totalTime = SystemClock.elapsedRealtime() - startRealtime;
            HwTimber.d("CTAPHID in: %s", responseApdu);
            HwTimber.d("CTAPHID communication took %dms", totalTime);
        }
        return responseApdu;
    }

    private static boolean isCtap2Apdu(CommandApdu commandApdu) {
        return commandApdu.getCLA() == FIDO2_CLA_PROPRIETARY && commandApdu.getINS() == FIDO2_INS
                && commandApdu.getP1() == FIDO2_P1 && commandApdu.getP2() == FIDO2_P2;
    }

    @Override
    public boolean isExtendedLengthSupported() {
        return true;
    }

    @Override
    public void release() {
        if (!released) {
            HwTimber.d("Usb transport disconnected");
            this.released = true;
            usbConnection.releaseInterface(usbInterface);
            if (transportReleasedCallback != null) {
                transportReleasedCallback.onTransportReleased();
            }
        }
    }

    @Override
    public TransportType getTransportType() {
        return TransportType.USB_CTAPHID;
    }

    @Override
    public boolean ping() {
        return !released;
    }

    @Nullable
    @Override
    public SecurityKeyType getSecurityKeyTypeIfAvailable() {
        return UsbSecurityKeyTypes.getSecurityKeyTypeFromUsbDeviceInfo(
                usbDevice.getVendorId(), usbDevice.getProductId(), usbConnection.getSerial());
    }
}
