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

package de.cotech.hw.internal.transport.usb;


import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;

import androidx.annotation.AnyThread;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import timber.log.Timber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbConnectionDispatcher {
    private static final String ACTION_USB = "de.cotech.hw.ACTION_USB";

    private final Context context;
    private final UsbDeviceManager usbDeviceManager;
    private final UsbManager usbManager;
    private final boolean disableUsbPermissionFallback;
    private IntentFilter intentFilter;
    private UsbDevice usbDeviceRequestedPermissions;

    public UsbConnectionDispatcher(Context context, UsbDeviceManager usbDeviceManager, boolean disableUsbPermissionFallback) {
        this.context = context.getApplicationContext();
        this.usbDeviceManager = usbDeviceManager;
        this.usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        this.disableUsbPermissionFallback = disableUsbPermissionFallback;

        intentFilter = new IntentFilter(ACTION_USB);
    }

    private final BroadcastReceiver usbBroadcastReceiver = new BroadcastReceiver() {
        @Override
        @UiThread
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) {
                return;
            }
            Timber.d("Callback: %s", intent);

            if (ACTION_USB.equals(action)) {
                usbDeviceRequestedPermissions = null;
                UsbDevice usbDevice = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                handleConnectedUsbDevice(usbDevice, false);
            }
        }
    };


    @UiThread
    private boolean handleConnectedUsbDevice(UsbDevice usbDevice, boolean requestPermission) {
        if (usbDeviceManager.refreshDeviceIfManaged(usbDevice)) {
            Timber.d("Refreshed already managed device (0x%s 0x%s)",
                    Integer.toHexString(usbDevice.getVendorId()), Integer.toHexString(usbDevice.getProductId()));
            return false;
        }
        if (!usbDeviceManager.isRelevantDevice(usbDevice)) {
            Timber.d("Ignoring unknown security key USB device (%s)", usbDevice);
            return false;
        }

        if (usbManager.hasPermission(usbDevice)) {
            Timber.d("Permission for device already available!");

            usbDeviceManager.initializeUsbDevice(usbDevice);
            return false;
        }

        if (requestPermission && !disableUsbPermissionFallback) {
            requestPermissionForUsbDevice(usbDevice);
            return true;
        }

        Timber.d("Didn't get permission for security key, giving up.");
        return false;
    }

    @UiThread
    public void onResume() {
        context.registerReceiver(usbBroadcastReceiver, intentFilter);
    }

    @UiThread
    public void onPause() {
        context.unregisterReceiver(usbBroadcastReceiver);
    }

    @UiThread
    public boolean rescanDevices(boolean requestPermission) {
        // never request permissions if we are still waiting for one!
        if (usbDeviceRequestedPermissions != null) {
            requestPermission = false;
        }

        Timber.d("Actively scanning for USB devices");
        for (UsbDevice usbDevice : usbManager.getDeviceList().values()) {
            if (usbDevice == usbDeviceRequestedPermissions) {
                continue;
            }
            if (handleConnectedUsbDevice(usbDevice, requestPermission)) {
                return true;
            }
        }

        return false;
    }

    @UiThread
    private void requestPermissionForUsbDevice(UsbDevice usbDevice) {
        UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        if (usbManager == null) {
            return;
        }

        usbDeviceRequestedPermissions = usbDevice;

        Intent answerBroadcastIntent = new Intent(ACTION_USB);
        answerBroadcastIntent.setPackage(context.getApplicationInfo().packageName);
        PendingIntent answerPendingIntent = PendingIntent.getBroadcast(context, 0, answerBroadcastIntent, 0);

        Timber.d("Requesting permission for %s", usbDevice.getDeviceName());
        usbManager.requestPermission(usbDevice, answerPendingIntent);
    }

    @AnyThread
    public static boolean isUsbHostModeAvailable(Context context) {
        return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_USB_HOST);
    }
}
