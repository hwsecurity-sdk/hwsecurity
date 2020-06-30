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

package de.cotech.hw.internal.transport.usb;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.util.Pair;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.util.Arrays;


@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbUtils {
    /**
     * Get a USB interface's input and output endpoints of a specified type.
     *
     * @param usbInterface usb device interface
     * @param usbEndpointType the type of endpoint
     * @return pair of input and output endpoints
     */
    @NonNull
    public static Pair<UsbEndpoint, UsbEndpoint> getIoEndpoints(UsbInterface usbInterface, int usbEndpointType) {
        UsbEndpoint bulkIn = null;
        UsbEndpoint bulkOut = null;
        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() != usbEndpointType) {
                continue;
            }

            if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                bulkIn = endpoint;
            } else if (endpoint.getDirection() == UsbConstants.USB_DIR_OUT) {
                bulkOut = endpoint;
            }
        }
        return new Pair<>(bulkIn, bulkOut);
    }

    /**
     * @param usbInterface usb device interface
     * @return true if input and output endpoints of the specified type exist
     */
    private static boolean checkHasIoInterruptEndpoints(UsbInterface usbInterface) {
        boolean hasIn = false;
        boolean hasOut = false;
        for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
            UsbEndpoint endpoint = usbInterface.getEndpoint(i);
            if (endpoint.getType() != UsbConstants.USB_ENDPOINT_XFER_INT) {
                continue;
            }

            if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                hasIn = true;
            } else if (endpoint.getDirection() == UsbConstants.USB_DIR_OUT) {
                hasOut = true;
            }
        }
        return hasIn && hasOut;
    }

    static List<UsbInterface> getCcidAndCtapHidInterfaces(UsbDevice device) {
        List<UsbInterface> result = new ArrayList<>();
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface usbInterface = device.getInterface(i);
            if (usbInterfaceLooksLikeCcid(usbInterface)) {
                result.add(usbInterface);
            } else if (usbInterfaceLooksLikeCtapHid(usbInterface)) {
                result.add(usbInterface);
            }
        }
        return result;
    }

    static boolean usbInterfaceLooksLikeCtapHid(UsbInterface usbInterface) {
        return usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID &&
                UsbUtils.checkHasIoInterruptEndpoints(usbInterface);
    }

    static boolean usbInterfaceLooksLikeCcid(UsbInterface usbInterface) {
        return usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_CSCID;
    }

    private static final int USB_RECIPIENT_INTERFACE = 0x01;
    private static final int USB_REQUEST_GET_DESCRIPTOR = 0x06;
    private static final int USB_DESCRIPTOR_HID_REPORT = 0x22;

    public static byte[] requestHidReportDescriptor(UsbDeviceConnection usbConnection, int interfaceIndex)
            throws IOException {
        byte[] buf = new byte[256];
        int bytesRead = usbConnection.controlTransfer(
                UsbConstants.USB_DIR_IN | USB_RECIPIENT_INTERFACE,
                USB_REQUEST_GET_DESCRIPTOR,
                USB_DESCRIPTOR_HID_REPORT << 8,
                interfaceIndex,
                buf,
                buf.length,
                50);
        if (bytesRead < 0) {
            throw new IOException("Unable to retrieve CTAPHID Report data");
        }
        return Arrays.copyOf(buf, bytesRead);
    }

    public static boolean isDeviceStillConnected(UsbManager usbManager, UsbDevice usbDevice) {
        return usbManager.getDeviceList().containsValue(usbDevice);
    }
}
