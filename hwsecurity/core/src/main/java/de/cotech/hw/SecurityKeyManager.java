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


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import android.app.Activity;
import android.app.Application;
import android.app.Application.ActivityLifecycleCallbacks;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;

import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.OnLifecycleEvent;
import de.cotech.hw.internal.dispatch.UsbIntentDispatchActivity;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.internal.transport.nfc.NfcConnectionDispatcher;
import de.cotech.hw.internal.transport.nfc.NfcTagManager;
import de.cotech.hw.internal.transport.nfc.NfcTransport;
import de.cotech.hw.internal.transport.usb.UsbConnectionDispatcher;
import de.cotech.hw.internal.transport.usb.UsbDeviceManager;
import de.cotech.hw.util.HwTimber;
import de.cotech.hw.util.HwTimber.DebugTree;


/**
 * The SecurityKeyManager is a singleton class for high-level management operations of security keys.
 * <p>
 * To use security keys in your App, you must first initialize it using {@link #init(Application)}.
 * This is usually done in {@link Application#onCreate}.
 * <p>
 * Once initialized, this class will dispatch newly connected security keys to all currently registered listeners.
 * Listeners can be registered with {@link #registerCallback}.
 * <p>
 * <pre>{@code
 * public void onCreate() {
 *     super.onCreate();
 *     SecurityKeyManager securityKeyManager = SecurityKeyManager.getInstance();
 *     securityKeyManager.init(this);
 * }
 * }</pre>
 * <p>
 * A callback is registered together with a {@link SecurityKeyConnectionMode}, which establishes a
 * connection to a particular type of Security Token, such as FIDO, PIV, or OpenPGP.  Implementations
 * for different SecurityKeyConnectionModes are shipped as modules, such as :de.cotech:hwsecurity-fido:,
 * :de.cotech:hwsecurity-piv:, and :de.cotech:hwsecurity-openpgp:. Apps will typically use only a
 * single type of Security Key.
 * <p>
 * To receive callbacks in an Activity, register for a callback bound to the Activity's lifecycle:
 * <p>
 * <pre>{@code
 * public void onCreate() {
 *     super.onResume();
 *     FidoSecurityKeyConnectionMode connectionMode = new FidoSecurityKeyConnectionMode();
 *     SecurityKeyManager.getInstance().registerCallback(connectionMode, this, this);
 * }
 * public void onSecurityKeyDiscovered(FidoSecurityKey securityKey) {
 *     // perform operations on FidoSecurityKey
 * }
 * }</pre>
 * <p>
 * Advanced applications that want to work with different applets on the same connected Security Key
 * can do so using {@link de.cotech.hw.raw.RawSecurityKeyConnectionMode}.
 */
public class SecurityKeyManager {
    private ArrayList<RegisteredConnectionMode<?>> registeredCallbacks = new ArrayList<>();

    private static SecurityKeyManager INSTANCE;

    private Application application;
    private SecurityKeyManagerConfig config;
    private UsbDeviceManager usbDeviceManager;
    private NfcTagManager nfcTagManager;
    private Handler callbackHandlerMain;
    private Handler callbackHandlerWorker;

    private List<SecurityKey> persistentSecurityKeys = new ArrayList<>(8);
    private AtomicBoolean callbackDedup = new AtomicBoolean(false);

    /**
     * Returns the singleton instance of SecurityKeyManager.
     */
    public static SecurityKeyManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SecurityKeyManager();
        }
        return INSTANCE;
    }

    private SecurityKeyManager() {
    }

    /**
     * This method initializes SecurityKeyManager with a default configuration.
     *
     * @throws IllegalStateException if already initialized
     * @see #init(Application, SecurityKeyManagerConfig)
     * @see SecurityKeyManagerConfig#getDefaultConfig()
     */
    @SuppressWarnings({ "WeakerAccess", "unused" }) // public API
    public void init(@NonNull Application application) {
        SecurityKeyManagerConfig config = SecurityKeyManagerConfig.getDefaultConfig();
        init(application, config);
    }

    /**
     * This method initializes SecurityKeyManager.
     *
     * This method initializes dispatch of security keys while the App is in the foreground. It must be called before
     * callbacks can be registered with {@link #registerCallbackForever}.
     *
     * @throws IllegalStateException if already initialized
     * @see SecurityKeyManagerConfig
     */
    @MainThread
    public void init(@NonNull Application application, @NonNull SecurityKeyManagerConfig securityKeyManagerConfig) {
        // noinspection ConstantConditions
        if (application == null) {
            throw new NullPointerException("config must not be null!");
        }
        // noinspection ConstantConditions
        if (securityKeyManagerConfig == null) {
            throw new NullPointerException("config must not be null!");
        }
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            throw new IllegalStateException("SecurityKeyManager.init must be called on the main thread!");
        }
        if (config != null) {
            throw new IllegalStateException("SecurityKeyManager was already initialized!");
        }

        config = securityKeyManagerConfig;
        this.application = application;

        HwTimber.Tree loggingTree = config.getLoggingTree();
        if (loggingTree != null && HwTimber.treeCount() == 0) {
            HwTimber.plant(loggingTree);
        }

        if (config.isEnableDebugLogging() && HwTimber.treeCount() == 0) {
            HwTimber.plant(new DebugTree() {
                @Override
                protected String createStackElementTag(@NonNull StackTraceElement element) {
                    if (element.getClassName().startsWith("de.cotech.hw")) {
                        return super.createStackElementTag(element);
                    } else {
                        return null;
                    }
                }

                @Override
                protected boolean isLoggable(String tag, int priority) {
                    return tag != null;
                }
            });
        }

        HandlerThread handlerThread = new HandlerThread("security-key-dispatcher");
        handlerThread.start();
        this.callbackHandlerWorker = new Handler(handlerThread.getLooper());
        this.callbackHandlerMain = new Handler(); // we make sure this is the main thread above

        usbDeviceManager = UsbDeviceManager.createInstance(application,
                this::transportConnectAndDeliverOrPostponeOrFail,
                callbackHandlerWorker, config.isAllowUntestedUsbDevices(), config.isEnableDebugLogging());
        nfcTagManager = NfcTagManager.createInstance(
                this::transportConnectAndDeliverOrPostponeOrFail,
                callbackHandlerWorker, config.isEnableDebugLogging(), config.isEnablePersistentNfcConnection());
        application.registerActivityLifecycleCallbacks(activityLifecycleCallbacks);

        installCotechProviderIfAvailable();
    }

    private void installCotechProviderIfAvailable() {
        try {
            Class<?> securityProviderClass = Class.forName("de.cotech.hw.provider.CotechSecurityKeyProvider");
            securityProviderClass.getDeclaredMethod("installProvider").invoke(null);
            HwTimber.d("CotechSecurityKeyProvider installed");
        } catch (ClassNotFoundException e) {
            // provider not available - never mind
        } catch (Exception e) {
            HwTimber.e(e, "CotechSecurityKeyProvider available, but failed to install!");
        }
    }

    private DispatcherActivityLifecycleCallbacks activityLifecycleCallbacks = new DispatcherActivityLifecycleCallbacks();

    @AnyThread
    private void ignoreNfcTransport(NfcTransport transport) {
        if (activityLifecycleCallbacks.activeNfcDispatcher != null) {
            activityLifecycleCallbacks.activeNfcDispatcher.ignoreNfcTag(transport.getTag());
        }
    }

    @UiThread
    private class DispatcherActivityLifecycleCallbacks implements ActivityLifecycleCallbacks {
        private Activity boundActivity;
        private UsbConnectionDispatcher activeUsbDispatcher;
        private NfcConnectionDispatcher activeNfcDispatcher;

        private void bindToActivity(Activity activity) {
            if (isUsbDispatchActivity(activity)) {
                return;
            }
            if (config.getExcludedActivityClasses().contains(activity.getClass())) {
                HwTimber.d(
                        "Activity with class %s is excluded, skipping SecurityKeyManager lifecycle initialization.",
                        activity.getClass().getSimpleName());
                return;
            }
            if (activity == boundActivity) {
                return;
            }

            Context context = activity.getApplicationContext();
            if (isUsbHostModeAvailable()) {
                activeUsbDispatcher = new UsbConnectionDispatcher(context, usbDeviceManager,
                        config.isDisableUsbPermissionFallback());
            }
            if (isNfcHardwareAvailable()) {
                activeNfcDispatcher = new NfcConnectionDispatcher(activity, nfcTagManager,
                        config.isDisableNfcDiscoverySound());
            }
            boundActivity = activity;
        }

        private void unbindFromActivity(Activity activity) {
            if (activity != boundActivity) {
                return;
            }
            activeNfcDispatcher = null;
            activeUsbDispatcher = null;
            boundActivity = null;
        }

        @Override
        public void onActivityResumed(Activity activity) {
            bindToActivity(activity);
            if (activeUsbDispatcher != null) {
                activeUsbDispatcher.onResume();
            }
            if (activeNfcDispatcher != null) {
                activeNfcDispatcher.onResume();
            }
            postTriggerCallbacksActively();
        }

        @Override
        public void onActivityPaused(Activity activity) {
            if (boundActivity != activity) {
                return;
            }
            if (activeUsbDispatcher != null) {
                activeUsbDispatcher.onPause();
            }
            if (activeNfcDispatcher != null) {
                activeNfcDispatcher.onPause();
            }
        }

        @Override
        public void onActivityDestroyed(Activity activity) {
            unbindFromActivity(activity);
        }

        @Override
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        }

        @Override
        public void onActivityStarted(Activity activity) {
        }

        @Override
        public void onActivityStopped(Activity activity) {
        }

        @Override
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        private boolean isUsbDispatchActivity(Activity activity) {
            return activity instanceof UsbIntentDispatchActivity;
        }
    }

    @UiThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void onNfcIntent(Intent intent) {
        nfcTagManager.onNfcIntent(intent);
    }

    @UiThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void onUsbIntent(Intent intent) {
        usbDeviceManager.onUsbIntent(intent);
    }

    @WorkerThread
    private void transportConnectAndDeliverOrPostponeOrFail(Transport transport) {
        try {
            transport.connect();
        } catch (IOException e) {
            HwTimber.e(e, "Failed initial connection with card");
            transport.release();
            return;
        }

        boolean hasInactiveModes = false;
        for (RegisteredConnectionMode<?> mode : registeredCallbacks) {
            if (!mode.isActive) {
                hasInactiveModes = true;
            }
            if (mode.transportAttemptImmediate(transport, hasInactiveModes)) {
                return;
            }
        }

        HwTimber.i("Discovered transport not delivered immediately: %s", transport.getClass().getSimpleName());

        for (RegisteredConnectionMode<?> mode : registeredCallbacks) {
            if (mode.transportAttemptPostpone(transport)) {
                return;
            }
        }

        HwTimber.i("Unhandled transport %s", transport.getClass().getSimpleName());
    }

    @AnyThread
    private void postTriggerCallbacksActively() {
        if (callbackDedup.getAndSet(true)) {
            return;
        }
        callbackHandlerMain.post(() -> {
            callbackDedup.set(false);
            if (hasActiveCallbacks() && activityLifecycleCallbacks.activeUsbDispatcher != null) {
                triggerCallbacksActively();
            }
        });
    }

    @UiThread
    private void triggerCallbacksActively() {
        if (activityLifecycleCallbacks.activeUsbDispatcher.rescanDevices(true)) {
            return;
        }

        for (SecurityKey securityKey : persistentSecurityKeys) {
            for (RegisteredConnectionMode<?> registeredMode : registeredCallbacks) {
                if (registeredMode.maybeRedeliverSecurityKey(securityKey)) {
                    return;
                }
            }
        }
    }

    private boolean hasActiveCallbacks() {
        for (RegisteredConnectionMode<?> mode : registeredCallbacks) {
            if (!mode.isBoundForever && mode.isActive) {
                return true;
            }
        }
        return false;
    }

    /**
     * Registers a callback for when a security key is discovered.
     *
     * @throws IllegalArgumentException if LifecycleOwner is an excluded class, see {@link SecurityKeyManagerConfig.Builder#addExcludedActivityClass}.
     */
    public <T extends SecurityKey> void registerCallback(SecurityKeyConnectionMode<T> mode,
            LifecycleOwner lifecycleOwner, SecurityKeyCallback<T> callback) {
        if (config == null) {
            throw new IllegalStateException("SecurityKeyManager must be initialized in your Application class!");
        }
        if (config.getExcludedActivityClasses().contains(lifecycleOwner.getClass())) {
            throw new IllegalArgumentException(
                    "Cannot registerCallback for Activity with excluded class " +
                            lifecycleOwner.getClass().getSimpleName() + ". " +
                            "This is a programming error, check your SecurityKeyManagerConfig.");
        }
        RegisteredConnectionMode<T> registeredConnectionMode = new RegisteredConnectionMode<>(mode, callback, false);
        lifecycleOwner.getLifecycle().addObserver(registeredConnectionMode);
        registeredCallbacks.add(0, registeredConnectionMode);

        postTriggerCallbacksActively();
    }

    /**
     * Registers a callback for when a security key is discovered.
     */
    @UiThread
    @SuppressWarnings({ "WeakerAccess", "unused" }) // public API
    public <T extends SecurityKey> void registerCallbackForever(SecurityKeyConnectionMode<T> mode,
            SecurityKeyCallback<T> callback) {
        if (config == null) {
            throw new IllegalStateException("SecurityKeyManager must be initialized in your Application class!");
        }
        registeredCallbacks.add(0, new RegisteredConnectionMode<>(mode, callback, true));
    }

    @SuppressWarnings("WeakerAccess") // public API
    public List<SecurityKey> getConnectedPersistentSecurityKeys() {
        return Collections.unmodifiableList(persistentSecurityKeys);
    }

    @SuppressWarnings({ "unused" }) // public API
    public <T> List<T> getConnectedPersistentSecurityKeys(Class<T> clazz) {
        ArrayList<T> result = new ArrayList<>();
        for (SecurityKey securityKey : persistentSecurityKeys) {
            if (clazz.isInstance(securityKey)) {
                // noinspection unchecked, this is checked right above
                result.add((T) securityKey);
            }
        }
        return Collections.unmodifiableList(result);
    }

    @AnyThread
    public void rediscoverConnectedSecurityKeys() {
        postTriggerCallbacksActively();
    }

    /**
     * Returns true if USB host mode is available.
     *
     * The USB host mode hardware feature is necessary to connect USB accessories (such as Security Keys) to
     * an Android device. If this method returns false, the device does not support this feature. This
     * should be indicated to the user in the App's user interface.
     */
    @SuppressWarnings("WeakerAccess") // part of our public API
    public boolean isUsbHostModeAvailable() {
        return UsbConnectionDispatcher.isUsbHostModeAvailable(application.getApplicationContext());
    }

    /**
     * Returns true iff NFC hardware is available.
     *
     * Note that NFC hardware might still be disabled, e.g. if the device is in "flight mode". You can use the
     * {@link de.cotech.hw.util.NfcStatusObserver} helper class to check this status and receive callbacks when
     * it changes.
     */
    public boolean isNfcHardwareAvailable() {
        return NfcConnectionDispatcher.isNfcHardwareAvailable(application.getApplicationContext());
    }

    private class RegisteredConnectionMode<T extends SecurityKey> implements LifecycleObserver {
        final SecurityKeyConnectionMode<T> connectionMode;
        final SecurityKeyCallback<T> callback;
        boolean isActive;
        boolean isBoundForever;
        @Nullable
        Transport postponedTransport;

        RegisteredConnectionMode(SecurityKeyConnectionMode<T> connectionMode, SecurityKeyCallback<T> callback,
                boolean isActive) {
            this.connectionMode = connectionMode;
            this.callback = callback;
            this.isActive = isActive;
            this.isBoundForever = isActive;

            HwTimber.d("%s for %s created",
                    connectionMode.getClass().getSimpleName(), callback.getClass().getSimpleName());
        }

        @WorkerThread
        boolean transportAttemptImmediate(Transport transport, boolean hasInactiveModes) {
            if (isBoundForever && hasInactiveModes) {
                return false;
            }
            if (!isActive || !connectionMode.isRelevantTransport(transport)) {
                return false;
            }
            return attemptConnectWithRegisteredSecurityMode(transport);
        }

        @WorkerThread
        boolean transportAttemptPostpone(Transport transport) {
            if (isBoundForever) {
                return false;
            }
            if (!isActive && connectionMode.isRelevantTransport(transport)) {
                HwTimber.d("Postponing callback for paused %s callback", connectionMode.getClass().getSimpleName());
                postponedTransport = transport;
                return true;
            }
            return false;
        }

        @UiThread
        private void maybeDeliverPostponedTransport() {
            final Transport deliveredTransport = this.postponedTransport;
            if (deliveredTransport == null) {
                return;
            }
            this.postponedTransport = null;

            if (deliveredTransport.isReleased()) {
                HwTimber.d("Postponed transport already released, holding off on delivering");
                return;
            }

            HwTimber.d("Delivering postponed transport");
            callbackHandlerWorker.post(() ->
                    attemptConnectWithRegisteredSecurityMode(deliveredTransport));
        }

        @UiThread
        boolean maybeRedeliverSecurityKey(SecurityKey securityKeyCandidate) {
            if (!isBoundForever && isActive && postponedTransport == null &&
                    connectionMode.isRelevantSecurityKey(securityKeyCandidate)) {
                // noinspection unchecked, this is checked with isRelevantSecurityKey
                deliverDiscover((T) securityKeyCandidate);
                return true;
            }
            return false;
        }

        @WorkerThread
        private boolean attemptConnectWithRegisteredSecurityMode(Transport transport) {
            T securityKey;
            try {
                securityKey = connectionMode.establishSecurityKeyConnection(config, transport);
                if (securityKey == null) {
                    return false;
                }
            } catch (IOException e) {
                callbackHandlerMain.post(() -> {
                    if (!isActive) {
                        HwTimber.d("%s no longer active - onSecurityKeyDiscoveryFailed callback!",
                                connectionMode.getClass().getSimpleName());
                        return;
                    }
                    callback.onSecurityKeyDiscoveryFailed(e);
                });
                return true;
            }

            if (securityKey.transport.isPersistentConnectionAllowed()) {
                persistentSecurityKeys.add(securityKey);
            }

            deliverDiscover(securityKey);
            return true;
        }

        @AnyThread
        private void deliverDiscover(T securityKey) {
            securityKey.transport.setTransportReleaseCallback(() -> handleTransportRelease(securityKey));

            callbackHandlerMain.post(() -> {
                if (!isActive) {
                    HwTimber.d("%s no longer active - dropping onSecurityKeyDiscovered callback!",
                            connectionMode.getClass().getSimpleName());
                    return;
                }
                callback.onSecurityKeyDiscovered(securityKey);
            });
        }

        @AnyThread
        private void handleTransportRelease(T securityKey) {
            persistentSecurityKeys.remove(securityKey);

            boolean isNfcTransport = securityKey.transport instanceof NfcTransport;
            if (isNfcTransport && config.isIgnoreNfcTagAfterUse()) {
                ignoreNfcTransport((NfcTransport) securityKey.transport);
            }

            if (isActive && securityKey.transport.isPersistentConnectionAllowed()) {
                callbackHandlerMain.post(() -> {
                    if (!isActive) {
                        HwTimber.d("%s no longer active - dropping onSecurityKeyDisconnected callback!",
                                connectionMode.getClass().getSimpleName());
                        return;
                    }
                    callback.onSecurityKeyDisconnected(securityKey);
                });
            }
        }

        @OnLifecycleEvent(Event.ON_RESUME)
        @UiThread
        void onResume() {
            HwTimber.d("onResume: %s for %s active",
                    connectionMode.getClass().getSimpleName(), callback.getClass().getSimpleName());
            isActive = true;

            maybeDeliverPostponedTransport();
        }

        @OnLifecycleEvent(Event.ON_PAUSE)
        @UiThread
        void onPause() {
            HwTimber.d("onPause: %s for %s inactive",
                    connectionMode.getClass().getSimpleName(), callback.getClass().getSimpleName());
            isActive = false;
        }

        @OnLifecycleEvent(Event.ON_DESTROY)
        @UiThread
        void onDestroy() {
            HwTimber.d("onDestroy: %s for %s destroyed",
                    connectionMode.getClass().getSimpleName(), callback.getClass().getSimpleName());
            registeredCallbacks.remove(this);
            postponedTransport = null;
        }
    }
}
