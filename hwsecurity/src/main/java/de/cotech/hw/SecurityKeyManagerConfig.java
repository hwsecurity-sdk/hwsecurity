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


import android.app.Application;

import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;
import de.cotech.hw.internal.dispatch.UsbIntentDispatchActivity;
import de.cotech.hw.util.HwTimber;


/**
 * This class holds configuration options for SecurityKeyManager.
 *
 * @see SecurityKeyManager#init(Application, SecurityKeyManagerConfig)
 */
@AutoValue
public abstract class SecurityKeyManagerConfig {
    public abstract boolean isDisableUsbPermissionFallback();
    public abstract boolean isAllowUntestedUsbDevices();
    public abstract boolean isEnableDebugLogging();
    @Nullable
    public abstract HwTimber.Tree getLoggingTree();
    public abstract boolean isEnableNfcTagMonitoring();
    public abstract boolean isDisableNfcDiscoverySound();

    static SecurityKeyManagerConfig getDefaultConfig() {
        return new Builder()
                .build();
    }

    /**
     *  Builder for SecurityKeyManagerConfig.
     */
    @SuppressWarnings({ "unused", "WeakerAccess", "UnusedReturnValue" })
    public static class Builder {
        private boolean disableUsbPermissionFallback = false;
        private boolean isAllowUntestedUsbDevices = false;
        private boolean isEnableDebugLogging = false;
        private HwTimber.Tree loggingTree = null;
        private boolean isEnableNfcTagMonitoring = false;
        private boolean isDisableNfcDiscoverySound = false;

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
         * Set a custom logging Tree.
         * <p>
         * This tree overrides {@link SecurityKeyManagerConfig.Builder#setEnableDebugLogging(boolean)}.
         */
        public Builder setLoggingTree(HwTimber.Tree loggingTree) {
            this.loggingTree = loggingTree;
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
            return new AutoValue_SecurityKeyManagerConfig(
                    disableUsbPermissionFallback,
                    isAllowUntestedUsbDevices,
                    isEnableDebugLogging,
                    loggingTree,
                    isEnableNfcTagMonitoring,
                    isDisableNfcDiscoverySound
            );
        }
    }
}
