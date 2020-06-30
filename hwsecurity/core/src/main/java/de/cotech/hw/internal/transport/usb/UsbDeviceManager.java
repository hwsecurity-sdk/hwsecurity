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
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.hardware.usb.UsbRequest;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.os.Handler;

import androidx.annotation.AnyThread;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.internal.transport.usb.ccid.UsbCcidTransport;
import de.cotech.hw.internal.transport.usb.ctaphid.UsbCtapHidTransport;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


public class UsbDeviceManager {
    private final OnDiscoveredUsbDeviceListener callback;
    private final android.os.Handler callbackHandler;
    private final boolean allowUntested;
    private boolean enableDebugLogging;

    private final UsbManager usbManager;

    private final HashMap<UsbDevice, ManagedUsbDevice> managedUsbDevices = new HashMap<>();

    public static UsbDeviceManager createInstance(Context context, OnDiscoveredUsbDeviceListener callback,
                                                  Handler handler, boolean allowUntested, boolean enableDebugLogging) {
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        return new UsbDeviceManager(usbManager, callback, handler, allowUntested, enableDebugLogging);
    }

    private UsbDeviceManager(UsbManager usbManager, OnDiscoveredUsbDeviceListener callback,
            Handler handler, boolean allowUntested, boolean enableDebugLogging) {
        this.callback = callback;
        this.callbackHandler = handler;
        this.allowUntested = allowUntested;
        this.usbManager = usbManager;
        this.enableDebugLogging = enableDebugLogging;
    }

    @UiThread
    public void onUsbIntent(Intent intent) {
        UsbDevice usbDevice = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
        if (usbDevice == null) {
            HwTimber.e("Got USB discovery intent, but missing device extra!");
            HwTimber.e("Intent: %s", intent);
            return;
        }
        initializeUsbDevice(usbDevice);
    }

    @UiThread
    void initializeUsbDevice(UsbDevice usbDevice) {
        if (!isRelevantDevice(usbDevice)) {
            HwTimber.d("Ignoring unknown security key USB device (%s)", usbDevice.getDeviceName());
            return;
        }

        synchronized (managedUsbDevices) {
            if (managedUsbDevices.containsKey(usbDevice)) {
                HwTimber.d("USB security key already managed, ignoring (%s)", usbDevice.getDeviceName());
                return;
            }

            try {
                ManagedUsbDevice managedUsbDevice = createManagedUsbDevice(usbDevice);
                managedUsbDevices.put(usbDevice, managedUsbDevice);
            } catch (IOException e) {
                HwTimber.e(e, "Failed to initialize usb device!");
            }
        }
    }

    @UiThread
    boolean refreshDeviceIfManaged(UsbDevice usbDevice) {
        synchronized (managedUsbDevices) {
            ManagedUsbDevice managedUsbDevice = managedUsbDevices.get(usbDevice);
            if (managedUsbDevice == null) {
                return false;
            }

            try {
                managedUsbDevice.claimInterface();
            } catch (UsbTransportException e) {
                HwTimber.d("Failed to reclaim USB device, releasing (0x%s 0x%s)",
                        Integer.toHexString(usbDevice.getVendorId()), Integer.toHexString(usbDevice.getProductId()));
                managedUsbDevice.clearAllActiveUsbTransports();
                managedUsbDevices.remove(usbDevice);
                return false;
            }

            return true;
        }
    }

    @UiThread
    private ManagedUsbDevice createManagedUsbDevice(UsbDevice usbDevice) throws UsbTransportException {
        HwTimber.d("Initializing managed USB security key");

        List<UsbInterface> usbInterfaces = UsbUtils.getCcidAndCtapHidInterfaces(usbDevice);
        if (usbInterfaces.isEmpty()) {
            throw new UsbTransportException("USB error: No usable USB class interface found. (Is CCID mode enabled on your security key?)");
        }

        UsbDeviceConnection usbConnection = usbManager.openDevice(usbDevice);
        if (usbConnection == null) {
            throw new UsbTransportException("USB error: failed to connect to device");
        }
        HwTimber.d("USB connection: %s", usbConnection.getSerial());

        ManagedUsbDevice managedUsbDevice = new ManagedUsbDevice(usbDevice, usbConnection, usbInterfaces);
        managedUsbDevice.claimInterface();
        startMonitorThread(managedUsbDevice, usbInterfaces).start();
        return managedUsbDevice;
    }

    @AnyThread
    boolean isRelevantDevice(UsbDevice usbDevice) {
        boolean hasCcidInterface = false;
        for (int i = 0; i < usbDevice.getInterfaceCount(); i++) {
            UsbInterface usbInterface = usbDevice.getInterface(i);
            if (UsbUtils.usbInterfaceLooksLikeCtapHid(usbInterface)) {
                return true;
            }
            if (UsbUtils.usbInterfaceLooksLikeCcid(usbInterface)) {
                hasCcidInterface = true;
            }
        }
        if (!hasCcidInterface) {
            return false;
        }
        return allowUntested || UsbSecurityKeyTypes.isTestedSecurityKey(usbDevice.getVendorId(), usbDevice.getProductId());
    }

    private class ManagedUsbDevice {
        private UsbDevice usbDevice;
        private UsbDeviceConnection usbConnection;
        private List<UsbInterface> usbInterfaces;

        private Map<UsbInterface, Transport> currentActiveTransports = new HashMap<>();

        private ManagedUsbDevice(
                UsbDevice usbDevice, UsbDeviceConnection usbConnection, List<UsbInterface> usbInterfaces) {
            this.usbDevice = usbDevice;
            this.usbConnection = usbConnection;
            this.usbInterfaces = usbInterfaces;
        }

        @AnyThread
        synchronized void claimInterface() throws UsbTransportException {
            for (UsbInterface usbInterface : usbInterfaces) {
                HwTimber.d("(Re)claiming USB interface: %s", usbInterface);
                if (!usbConnection.claimInterface(usbInterface, true)) {
                    throw new UsbTransportException("USB error: failed to claim interface");
                }
            }
        }

        @AnyThread
        synchronized void clearAllActiveUsbTransports() {
            for (Entry<UsbInterface, Transport> entry : currentActiveTransports.entrySet()) {
                final Transport disconnectedTransport = entry.getValue();
                callbackHandler.post(disconnectedTransport::release);
            }
            currentActiveTransports.clear();
        }

        @AnyThread
        synchronized void clearActiveUsbTransport(UsbInterface usbInterface) {
            Transport disconnectedTransport = currentActiveTransports.remove(usbInterface);
            if (disconnectedTransport != null) {
                callbackHandler.post(disconnectedTransport::release);
            }
        }

        @AnyThread
        synchronized void createNewActiveUsbTransport(UsbInterface usbInterface) {
            if (currentActiveTransports.containsKey(usbInterface)) {
                HwTimber.d("Usb interface already connected");
                return;
            }

            Transport usbTransport;
            if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_CSCID) {
                usbTransport = UsbCcidTransport.createUsbTransport(
                        usbManager, usbDevice, usbConnection, usbInterface, enableDebugLogging);
            } else if (usbInterface.getInterfaceClass() == UsbConstants.USB_CLASS_HID) {
                usbTransport = UsbCtapHidTransport.createUsbTransport(
                        usbManager, usbDevice, usbConnection, usbInterface, enableDebugLogging);
            } else {
                throw new RuntimeException("unsupported USB class");
            }
            HwTimber.d("USB transport created on interface class %s", usbInterface.getInterfaceClass());
            currentActiveTransports.put(usbInterface, usbTransport);
            callbackHandler.post(() -> callback.usbTransportDiscovered(usbTransport));
        }
    }

    @UiThread
    private UsbMonitorThread startMonitorThread(ManagedUsbDevice managedUsbDevice, List<UsbInterface> usbInterfaces) {
        Map<UsbEndpoint, UsbInterface> interruptEndpoints = getIntEndpointsIfOnlyCcid(usbInterfaces);
        if (!interruptEndpoints.isEmpty()) {
            return new UsbInterruptMonitorThread(managedUsbDevice, interruptEndpoints);
        } else {
            return new UsbSimpleMonitorThread(managedUsbDevice, usbInterfaces);
        }
    }

    @WorkerThread
    private void onUsbDeviceLost(UsbDevice usbDevice) {
        HwTimber.d("Lost USB security key, dropping managed device");
        synchronized (managedUsbDevices) {
            ManagedUsbDevice managedUsbDevice = managedUsbDevices.get(usbDevice);
            if (managedUsbDevice == null) {
                HwTimber.d("Device already dropped");
                return;
            }
            managedUsbDevice.clearAllActiveUsbTransports();
            managedUsbDevices.remove(usbDevice);
        }
    }

    @WorkerThread
    private void onIccConnect(UsbDevice usbDevice, UsbInterface usbInterface) {
        synchronized (managedUsbDevices) {
            ManagedUsbDevice managedUsbDevice = managedUsbDevices.get(usbDevice);
            managedUsbDevice.createNewActiveUsbTransport(usbInterface);
        }
    }

    @WorkerThread
    private void onIccDisconnect(UsbDevice usbDevice, UsbInterface usbInterface) {
        if (VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
            HwTimber.d("ICC disconnected on interface %s", usbInterface.getName());
        }
        synchronized (managedUsbDevices) {
            ManagedUsbDevice managedUsbDevice = managedUsbDevices.get(usbDevice);
            managedUsbDevice.clearActiveUsbTransport(usbInterface);
        }
    }

    private abstract class UsbMonitorThread extends Thread {
        final ManagedUsbDevice managedUsbDevice;

        UsbMonitorThread(ManagedUsbDevice managedUsbDevice) {
            this.managedUsbDevice = managedUsbDevice;
        }

        @Override
        public void run() {
            try {
                loopMonitorUsb();
            } finally {
                onUsbDeviceLost(managedUsbDevice.usbDevice);
            }
        }

        @WorkerThread
        abstract void loopMonitorUsb();

        @WorkerThread
        void sleepInterruptibly(long time) {
            try {
                Thread.sleep(time);
            } catch (InterruptedException e) {
                // nvm
            }
        }

        @AnyThread
        boolean deviceIsStillConnected() {
            return UsbUtils.isDeviceStillConnected(usbManager, managedUsbDevice.usbDevice);
        }
    }

    private class UsbSimpleMonitorThread extends UsbMonitorThread {
        final List<UsbInterface> usbInterfaces;

        private UsbSimpleMonitorThread(ManagedUsbDevice managedUsbDevice, List<UsbInterface> usbInterfaces) {
            super(managedUsbDevice);
            this.usbInterfaces = usbInterfaces;
        }

        @WorkerThread
        void loopMonitorUsb() {
            HwTimber.d("Simple device, assuming all ICCs are connected");
            for (UsbInterface usbInterface : usbInterfaces) {
                onIccConnect(managedUsbDevice.usbDevice, usbInterface);
            }
            while (deviceIsStillConnected()) {
                sleepInterruptibly(250);
            }
        }
    }

    private class UsbInterruptMonitorThread extends UsbMonitorThread {
        // https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf
        // 6.3.1 RDR_to_PC_NotifySlotChange
        static final int CCID_NOTIFY_SLOT_CHANGE = 0x50;
        static final int ICC_SLOT_CHANGE_NOT_PRESENT = 0x02;
        static final int ICC_SLOT_CHANGE_PRESENT = 0x03;

        private final Map<UsbEndpoint, UsbInterface> usbInterruptEndpoints;

        private UsbInterruptMonitorThread(ManagedUsbDevice managedUsbDevice, Map<UsbEndpoint, UsbInterface> usbInterruptEndpoints) {
            super(managedUsbDevice);
            this.usbInterruptEndpoints = usbInterruptEndpoints;
        }

        @WorkerThread
        void loopMonitorUsb() {
            for (UsbEndpoint usbInterruptEndpoint : usbInterruptEndpoints.keySet()) {
                ByteBuffer responseBuffer = ByteBuffer.allocate(usbInterruptEndpoint.getMaxPacketSize());
                UsbRequest usbRequest = new UsbRequest();
                usbRequest.initialize(managedUsbDevice.usbConnection, usbInterruptEndpoint);
                usbRequest.setClientData(responseBuffer);
                usbRequest.queue(responseBuffer, responseBuffer.capacity());
            }

            HwTimber.d("Listening…");
            while (deviceIsStillConnected()) {
                UsbRequest returnedRequest = managedUsbDevice.usbConnection.requestWait();
                if (returnedRequest == null) {
                    HwTimber.d("Got error listening on interrupt endpoint");
                    break;
                }

                ByteBuffer responseBuffer = (ByteBuffer) returnedRequest.getClientData();
                responseBuffer.rewind();

                byte bMessageType = responseBuffer.get();
                switch (bMessageType) {
                    case CCID_NOTIFY_SLOT_CHANGE: {
                        // Note: All ICC devices we worked with so far had exactly one slot. We make the simplifying
                        // assumption here that this is always the case.
                        byte bmSlotIccState = responseBuffer.get();
                        UsbInterface usbInterface = usbInterruptEndpoints.get(returnedRequest.getEndpoint());
                        if (bmSlotIccState == ICC_SLOT_CHANGE_PRESENT) {
                            HwTimber.d("ICC state change: slot 0 connected");
                            onIccConnect(managedUsbDevice.usbDevice, usbInterface);
                        } else if (bmSlotIccState == ICC_SLOT_CHANGE_NOT_PRESENT) {
                            HwTimber.d("ICC state change: slot 0 disconnected");
                            onIccDisconnect(managedUsbDevice.usbDevice, usbInterface);
                        } else {
                            HwTimber.e("Ignoring unknown ICC state change 0x%x", bmSlotIccState);
                        }
                        break;
                    }
                    case 0x00: {
                        HwTimber.d("Ignoring 0x00 message on interrupt endpoint");
                        break;
                    }
                    default: {
                        HwTimber.e("Got unexpected message type 0x%x on interrupt endpoint!", bMessageType);
                        String bufferHex = Hex.encodeHexString(responseBuffer.array());
                        HwTimber.e("Buffer: %s", bufferHex);
                        break;
                    }
                }

                returnedRequest.queue(responseBuffer, responseBuffer.capacity());
                sleepInterruptibly(100);
            }
        }
    }

    @AnyThread
    private static Map<UsbEndpoint, UsbInterface> getIntEndpointsIfOnlyCcid(List<UsbInterface> usbInterfaces) {
        Map<UsbEndpoint, UsbInterface> result = new HashMap<>(usbInterfaces.size());
        for (UsbInterface usbInterface : usbInterfaces) {
            if (usbInterface.getInterfaceClass() != UsbConstants.USB_CLASS_CSCID) {
                return Collections.emptyMap();
            }
            for (int i = 0; i < usbInterface.getEndpointCount(); i++) {
                UsbEndpoint endpoint = usbInterface.getEndpoint(i);
                if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_INT &&
                        endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    result.put(endpoint, usbInterface);
                }
            }
        }
        return result;
    }

    public interface OnDiscoveredUsbDeviceListener {
        @WorkerThread
        void usbTransportDiscovered(Transport usbTransport);
    }
}
