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

package de.cotech.hw.internal.dispatch;


import android.app.Activity;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.SecurityKeyManagerConfig.Builder;
import de.cotech.hw.util.HwTimber;


/**
 * A pseudo-activity used in the USB dispatching process.
 * <p>
 * This class is optional, and shipped as an extra library (see below). If included, the App will be registered for
 * dispatching security keys connected via USB. <b>Without this, the app will be unable to persist permission to access
 * a USB security key.</b> To avoid asking the user for permission every time a USB security key connects, it is
 * recommended to include this class.
 * <p>
 * This is an internal class used for discovering USB security keys through the intent dispatch mechanism. It
 * should never be used directly, but automatically supplements the discovery mechanism in {@link SecurityKeyManager}.
 * <p>
 * To include this class, add the following to <code>build.gradle</code>:
 * <p>
 * <code>implementation 'de.cotech:hwsecurity-intent-usb:1.0'</code>
 *
 * @see Builder#setDisableUsbPermissionFallback(boolean)
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public final class UsbIntentDispatchActivity extends Activity {
    SecurityKeyManager securityKeyManager = SecurityKeyManager.getInstance();

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent == null || !UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(intent.getAction())) {
            return;
        }

        HwTimber.d("Usb Security Key connected!");
        securityKeyManager.onUsbIntent(intent);

        finish();
    }
}
