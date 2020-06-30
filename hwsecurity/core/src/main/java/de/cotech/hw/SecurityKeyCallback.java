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

package de.cotech.hw;

import androidx.annotation.NonNull;
import androidx.annotation.UiThread;

import java.io.IOException;

import de.cotech.hw.util.HwTimber;

/**
 * A callback interface when a security key is discovered.
 *
 * This interface is parametrized with a type of SecurityKey, and is typically passed to
 * {@link SecurityKeyManager#registerCallback} with a matching {@link SecurityKeyConnectionMode}.
 *
 * @see SecurityKeyConnectionMode
 * @see SecurityKeyManager#registerCallback
 */
public interface SecurityKeyCallback<T extends SecurityKey> {
    /**
     * Called when a security key is discovered.
     */
    @UiThread
    void onSecurityKeyDiscovered(@NonNull T securityKey);

    /**
     * Called when a security key was discovered, but failed to connect.
     *
     * This can typically happen when the connected Security Key does not contain the expected
     * applet, or the hardware is faulty. It is not generally advised to handle this error in a
     * user-facing way.
     */
    @UiThread
    default void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        HwTimber.e(exception, "Failed to connect to SecurityKey");
    }

    /**
     * Called when a persistently connected Security Key was disconnected.
     *
     * <p>
     * This callback is only called on Security Keys for which {@link SecurityKey#isPersistentlyConnected()}
     * returns true. This typically applies to USB devices, but can be applied to NFC devices as well if
     * persistent NFC connection has been enabled via {@link SecurityKeyManagerConfig.Builder#setEnablePersistentNfcConnection}.
     * Those Security Keys are also listed under {@link SecurityKeyManager#getConnectedPersistentSecurityKeys()}.
     *
     * <p>
     * Note that this callback will only be sent to the same registered callback that received the
     * {@link #onSecurityKeyDiscovered(SecurityKey)} callback, and will not be postponed for late
     * delivery if the callback isn't active.
     */
    @UiThread
    default void onSecurityKeyDisconnected(@NonNull T securityKey) { }
}
