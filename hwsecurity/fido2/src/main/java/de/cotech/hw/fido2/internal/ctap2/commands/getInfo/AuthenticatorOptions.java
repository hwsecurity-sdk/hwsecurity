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

package de.cotech.hw.fido2.internal.ctap2.commands.getInfo;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;


@AutoValue
public abstract class AuthenticatorOptions {
    // plat 	platform device: Indicates that the device is attached to the client and therefore can’t be removed and used on another client. 	false
    public abstract boolean plat();

    // rk 	resident key: Indicates that the device is capable of storing keys on the device itself and therefore can satisfy the authenticatorGetAssertion request with allowList parameter not specified or empty. 	false
    public abstract boolean rk();

    // clientPin
    // If present and set to true, it indicates that the device is capable of accepting a PIN from the client and PIN has been set.
    // If present and set to false, it indicates that the device is capable of accepting a PIN from the client and PIN has not been set yet.
    // If absent, it indicates that the device is not capable of accepting a PIN from the client.
    @Nullable
    public abstract Boolean clientPin();

    // up 	user presence: Indicates that the device is capable of testing user presence. 	true
    public abstract boolean up();

    // uv 	user verification: Indicates that the device is capable of verifying the user within itself. For example, devices with UI, biometrics fall into this category.
    // If present and set to true, it indicates that the device is capable of user verification within itself and has been configured.
    // If present and set to false, it indicates that the device is capable of user verification within itself and has not been yet configured. For example, a biometric device that has not yet been configured will return this parameter set to false.
    // If absent, it indicates that the device is not capable of user verification within itself.
    // A device that can only do Client PIN will not return the "uv" parameter.
    // If a device is capable of verifying the user within itself as well as able to do Client PIN, it will return both "uv" and the Client PIN option.
    @Nullable
    public abstract Boolean uv();

    public static AuthenticatorOptions create() {
        return create(null, null, null, null, null);
    }

    public static AuthenticatorOptions create(Boolean plat, Boolean rk, Boolean clientPin, Boolean up, Boolean uv) {
        if (plat == null) {
            plat = false;
        }
        if (rk == null) {
            rk = false;
        }
        if (up == null) {
            up = true;
        }

        return new AutoValue_AuthenticatorOptions(plat, rk, clientPin, up, uv);
    }
}
