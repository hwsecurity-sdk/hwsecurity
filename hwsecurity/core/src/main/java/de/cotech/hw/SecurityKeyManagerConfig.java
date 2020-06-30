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


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import android.app.Activity;
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

    public abstract boolean isEnablePersistentNfcConnection();

    public abstract boolean isIgnoreNfcTagAfterUse();

    public abstract boolean isDisableNfcDiscoverySound();

    public abstract List<Class<? extends Activity>> getExcludedActivityClasses();

    static SecurityKeyManagerConfig getDefaultConfig() {
        return new Builder()
                .build();
    }

    /**
     * Builder for SecurityKeyManagerConfig.
     */
    @SuppressWarnings({"unused", "WeakerAccess", "UnusedReturnValue"})
    public static class Builder {
        private boolean disableUsbPermissionFallback = false;
        private boolean isAllowUntestedUsbDevices = false;
        private boolean isEnableDebugLogging = false;
        private HwTimber.Tree loggingTree = null;
        private boolean isEnablePersistentNfcConnection = false;
        private boolean isIgnoreNfcTagAfterUse = false;
        private boolean isDisableNfcDiscoverySound = false;
        private ArrayList<Class<? extends Activity>> excludedActivityClasses = new ArrayList<>();

        /**
         * This setting controls USB permission request behavior.
         * <p>
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
         * <p>
         * While any spec-compliant device should work in theory, there are often quirks to specific devices that may
         * result in arbitrary bugs or insecure behavior. For this reason, the default is to ignore devices that
         * weren't explicitly tested and are known to work.
         *
         * @see <a href="https://hwsecurity.dev/docs/supported-hardware/">https://hwsecurity.dev/docs/supported-hardware/</a>
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
         * If you like to filter based on different priorities or delegate output to other logging frameworks
         * (by default Android’s Log class is used), a custom logging tree can be used.
         * Setting your own logging tree overrides setEnableDebugLogging(true).
         * <pre>{@code
         * .setLoggingTree(new HwTimber.DebugTree() {
         *     @Override
         *     protected String createStackElementTag(@NonNull StackTraceElement element) {
         *         if (element.getClassName().startsWith("de.cotech.hw")) {
         *             return super.createStackElementTag(element);
         *         } else {
         *             return null;
         *         }
         *     }
         *
         *     @Override
         *     protected boolean isLoggable(String tag, int priority) {
         *         if (tag == null) {
         *             return false;
         *         }
         *         // TODO: filter based on priority
         *     }
         *
         *     @Override
         *     protected void log(int priority, String tag, @NonNull String message, Throwable t) {
         *         // TODO: delegate log output to your own logging framework
         *     }
         * });
         * }</pre>
         * <p>
         * This tree overrides {@link SecurityKeyManagerConfig.Builder#setEnableDebugLogging(boolean)}.
         */
        public Builder setLoggingTree(HwTimber.Tree loggingTree) {
            this.loggingTree = loggingTree;
            return this;
        }

        /**
         * This setting enables presence monitoring for NFC tags, which will allow the use persistent of NFC tags.
         * <p>
         * Enable this setting if you need to retrieve NFC Security Keys via
         * {@link SecurityKeyManager#getConnectedPersistentSecurityKeys()}.
         */
        public Builder setEnablePersistentNfcConnection(boolean isEnablePersistentNfcConnection) {
            this.isEnablePersistentNfcConnection = isEnablePersistentNfcConnection;
            return this;
        }

        /**
         * This setting debounces the NFC tag for 1500 ms after it has been used.
         * <p>
         * Enable this setting to prevent other apps from detecting the NFC Security Key directly after
         * your app is closed. This could lead to a second vibration by Android's NFC system after
         * the tag has been used.
         */
        public Builder setIgnoreNfcTagAfterUse(boolean isIgnoreNfcTagAfterUse) {
            this.isIgnoreNfcTagAfterUse = isIgnoreNfcTagAfterUse;
            return this;
        }

        /**
         * This setting controls whether the platform sound upon discovery of an NFC device will be suppressed.
         * <p>
         * Note that, as of API level 28, there is no way to influence the platform sound other than enabling or
         * disabling.
         */
        public Builder setDisableNfcDiscoverySound(boolean isDisableNfcDiscoverySound) {
            this.isDisableNfcDiscoverySound = isDisableNfcDiscoverySound;
            return this;
        }

        /**
         * Add an Activity to the list of excluded Activities.
         * <p>
         * This adds a specific Activity to an exclusion list, making it exempt from the lifecycle
         * management by SecurityKeyManager. This effectively disables all features of the hwsecurity
         * SDK while this Activity is in the foreground. This is useful for Activities that manage
         * their own NFC or USB connections, for example by enabling NFC reader mode via
         * {@link android.nfc.NfcAdapter#enableReaderMode}, or yielding processing to a
         * {@link android.nfc.cardemulation.HostApduService}.
         * <p>
         * A call to the {@link SecurityKeyManager#registerCallback} method for an Activity that has
         * been excluded in this way will result in an {@link IllegalArgumentException}.
         *
         * <pre>{@code
         * new SecurityKeyManagerConfig.Builder()
         *   .addExcludedActivityClass(MyCustomNfcActivity.class)
         * }</pre>
         */
        public Builder addExcludedActivityClass(Class<? extends Activity> clazz) {
            this.excludedActivityClasses.add(clazz);
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
                    isEnablePersistentNfcConnection,
                    isIgnoreNfcTagAfterUse,
                    isDisableNfcDiscoverySound,
                    Collections.unmodifiableList(excludedActivityClasses)
            );
        }
    }
}
