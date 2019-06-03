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

package de.cotech.hw;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import android.app.Application;

import com.google.auto.value.AutoValue;
import de.cotech.hw.internal.dispatch.UsbIntentDispatchActivity;
import de.cotech.hw.util.Hex;


/**
 * This class holds configuration options for SecurityKeyManager.
 *
 * @see SecurityKeyManager#init(Application, SecurityKeyManagerConfig)
 */
@AutoValue
public abstract class SecurityKeyManagerConfig {
    private static final byte[] AID_SELECT_FILE_PIV = Hex.decodeHexOrFail("A000000308");

    public abstract List<byte[]> getPivAidPrefixes();
    public abstract boolean isDisableUsbPermissionFallback();
    public abstract boolean isAllowUntestedUsbDevices();
    public abstract boolean isEnableDebugLogging();
    public abstract boolean isEnableNfcTagMonitoring();
    public abstract boolean isDisableNfcDiscoverySound();

    static SecurityKeyManagerConfig getDefaultConfig() {
        return new Builder()
                .addDefaultPivAidPrefixes()
                .build();
    }

    /**
     *  Builder for SecurityKeyManagerConfig.
     */
    @SuppressWarnings({ "unused", "WeakerAccess", "UnusedReturnValue" })
    public static class Builder {
        private ArrayList<byte[]> pivAidPrefixes = new ArrayList<>();
        private boolean disableUsbPermissionFallback = false;
        private boolean isAllowUntestedUsbDevices = false;
        private boolean isEnableDebugLogging = false;
        private boolean isEnableNfcTagMonitoring = false;
        private boolean isDisableNfcDiscoverySound = false;

        /**
         * This adds the default OpenPGP-Card AID prefix to the list of accepted prefixes.
         *
         * Note that this prefix will be used by default if no explicit AID prefixes are added, so calling this method
         * is only useful if other prefixes have been added with {@link #addPivAidPrefix(String)}.
         */
        public Builder addDefaultPivAidPrefixes() {
            pivAidPrefixes.add(AID_SELECT_FILE_PIV);
            return this;
        }

        /**
         * This adds an AID prefix to the list of accepted prefixes for the PIV connection mode.
         *
         * Note that once an explicit prefix is added, the default prefix will no longer be included automatically.
         * To add the default back, use {@link #addDefaultPivAidPrefixes()}.
         *
         * @throws IllegalArgumentException if hexStringAidPrefix does not contain a valid hex-encoded byte sequence
         */
        public Builder addPivAidPrefix(String hexStringAidPrefix) {
            byte[] aidPrefix = Hex.decodeHexOrFail(hexStringAidPrefix);
            pivAidPrefixes.add(aidPrefix);
            return this;
        }

        /** This adds an AID prefix to the list of accepted prefixes. */
        public Builder addPivAidPrefix(byte[] aidPrefix) {
            aidPrefix = Arrays.copyOf(aidPrefix, aidPrefix.length);
            pivAidPrefixes.add(aidPrefix);
            return this;
        }

        /**
         * This setting controls USB permission request behavior.
         *
         * By default, when a compatible USB device is connected, {@link SecurityKeyManager} will automatically request
         * permission for the device to make it available in the callback. However, this is only a fallback mechanism
         * that is used when the Intent-based USB dispatch fails.
         *
         * @see UsbIntentDispatchActivity
         */
        public Builder setDisableUsbPermissionFallback(boolean disableUsbPermissionFallback) {
            this.disableUsbPermissionFallback = disableUsbPermissionFallback;
            return this;
        }

        /**
         * This setting controls whether "untested" USB devices will be dispatched or not.
         *
         * While any spec-compliant device should work in theory, there are often quirks to specific devices that may
         * result in arbitrary bugs or insecure behavior. For this reason, the default is to ignore devices that
         * weren't explicitly tested and are known to work.
         *
         * @see <a href="https://www.cotech.de/docs/hw-supported-hardware/">https://www.cotech.de/docs/hw-supported-hardware/</a>
         */
        public Builder setAllowUntestedUsbDevices(boolean allowUntestedUsbDevices) {
            this.isAllowUntestedUsbDevices = allowUntestedUsbDevices;
            return this;
        }

        /**
         * This setting controls whether debug logging will be enabled.
         * <p>
         * If debug logging is enabled, the raw traffic between security keys and the app will be included in regular
         * log output.
         */
        public Builder setEnableDebugLogging(boolean isEnableDebugLogging) {
            this.isEnableDebugLogging = isEnableDebugLogging;
            return this;
        }

        /**
         * This setting enables presence monitoring for NFC tags, which will allow the use persistent of NFC tags.
         *
         * Enable this setting if you need to retrieve NFC Security Keys via
         * {@link SecurityKeyManager#getConnectedPersistentSecurityKeys()}.
         */
        public Builder setEnableNfcTagMonitoring(boolean isEnableNfcTagMonitoring) {
            this.isEnableNfcTagMonitoring = isEnableNfcTagMonitoring;
            return this;
        }

        /**
         * This setting controls whether the platform sound upon discovery of an NFC device will be suppressed.
         * <p>
         * Note that, as of api level 28, there is no way to influence the platform sound other than enabling or
         * disabling.
         */
        public Builder setDisableNfcDiscoverySound(boolean isDisableNfcDiscoverySound) {
            this.isDisableNfcDiscoverySound = isDisableNfcDiscoverySound;
            return this;
        }

        /**
         * Constructs a SecurityKeyManagerConfig from the Builder.
         */
        public SecurityKeyManagerConfig build() {
            if (pivAidPrefixes.isEmpty()) {
                addDefaultPivAidPrefixes();
            }
            return new AutoValue_SecurityKeyManagerConfig(
                    Collections.unmodifiableList(pivAidPrefixes),
                    disableUsbPermissionFallback,
                    isAllowUntestedUsbDevices,
                    isEnableDebugLogging,
                    isEnableNfcTagMonitoring,
                    isDisableNfcDiscoverySound
            );
        }
    }
}
