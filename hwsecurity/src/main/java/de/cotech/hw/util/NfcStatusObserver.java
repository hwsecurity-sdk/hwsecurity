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

package de.cotech.hw.util;


import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Build.VERSION_CODES;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.OnLifecycleEvent;
import de.cotech.hw.SecurityKeyManager;


/**
 * A helper class to monitor whether NFC hardware is available and enabled.
 *
 * <p>
 * Note that this class does not communicate with the NFC device on its own - its only purpose is to tell when NFC
 * functionality is available, and has been enabled or disabled!
 *
 * <p>
 * Example:
 * <p>
 * <pre>{@code
 * public class NfcActionActivity extends AppCompatActivity {
 *     private NfcStatusObserver nfcStatusObserver;
 *
 *     @Override
 *     protected void onCreate(@Nullable Bundle savedInstanceState) {
 *         super.onCreate(savedInstanceState);
 *
 *         if (!SecurityKeyManager.getInstance().isNfcHardwareAvailable(this)) {
 *             startActivityToNicelyTellUserThatNfcHardwareIsUnavailable();
 *             finish();
 *             return;
 *         }
 *
 *         this.nfcStatusObserver = new NfcStatusObserver((Context) this, (LifecycleOwner) this,
 *                 isEnabled -> showOrHideNfcDisabledView(!isEnabled));
 *
 *         // this button should be part of the "nfc disabled view"
 *         View buttonPleaseEnableNfc = findViewById(R.id.buttonPleaseEnableNfc);
 *         buttonPleaseEnableNfc.setOnClickListener(view -> startAndroidNfcConfigActivityWithHint());
 *     }
 *
 *     private void startAndroidNfcConfigActivityWithHint() {
 *         Toast.makeText(getApplicationContext(),
 *                 "Please activate NFC and press Back to return to MyApplication", Toast.LENGTH_SHORT).show();
 *         startActivity(new Intent(android.provider.Settings.ACTION_NFC_SETTINGS));
 *     }
 *
 *     @Override
 *     protected void onResume() {
 *         super.onResume();
 *         // In case we missed a change while the activity was in the background
 *         showOrHideNfcDisabledView(!nfcStatusObserver.isNfcEnabled());
 *     }
 * }
 * }</pre>
 *
 */
public class NfcStatusObserver implements LifecycleObserver {
    private final Context context;
    @Nullable
    private final NfcAdapter nfcAdapter;
    private final NfcStatusCallback nfcStatusCallback;
    private BroadcastReceiver nfcStateBroadcastReceiver;

    /**
     * Constructs an NfcStatusObserver and binds it to a Lifecycle. The NfcStatusCallback will receive callbacks while
     * the lifecycle is in RESUMED state.
     * <p>
     * Note that since the observer is bound to the lifecycle, no cleanup of the callback is necessary.
     */
    @TargetApi(VERSION_CODES.JELLY_BEAN_MR2)
    public NfcStatusObserver(Context context, LifecycleOwner lifecycleOwner, NfcStatusCallback nfcStatusCallback) {
        if (context == null) {
            throw new NullPointerException("Context argument to NfcStatusObserver() must not be null!");
        }
        if (lifecycleOwner == null) {
            throw new NullPointerException("LifecycleOwner argument to NfcStatusObserver() must not be null!");
        }
        if (nfcStatusCallback == null) {
            throw new NullPointerException("NfcStatusCallback argument to NfcStatusObserver() must not be null!");
        }

        this.context = context;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(context);
        this.nfcStatusCallback = nfcStatusCallback;

        boolean hasNfcAdapter = nfcAdapter != null;
        if (hasNfcAdapter) {
            lifecycleOwner.getLifecycle().addObserver(this);
        }
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @OnLifecycleEvent(Event.ON_RESUME)
    public void onResume() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            registerNfcStateBroadcastListener();
        }
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @OnLifecycleEvent(Event.ON_PAUSE)
    public void onPause() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            unregisterNfcStateBroadcastListener();
        }
    }

    @TargetApi(VERSION_CODES.JELLY_BEAN_MR2)
    private void registerNfcStateBroadcastListener() {
        if (nfcStateBroadcastReceiver == null) {
            nfcStateBroadcastReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    int state = intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF);
                    switch (state) {
                        case NfcAdapter.STATE_ON:
                            nfcStatusCallback.onNfcDeviceStateChanged(true);
                            break;
                        case NfcAdapter.STATE_OFF:
                            nfcStatusCallback.onNfcDeviceStateChanged(false);
                            break;
                    }
                }
            };
        }
        IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED);
        context.registerReceiver(nfcStateBroadcastReceiver, filter);
    }

    @TargetApi(VERSION_CODES.JELLY_BEAN_MR2)
    private void unregisterNfcStateBroadcastListener() {
        context.unregisterReceiver(nfcStateBroadcastReceiver);
    }

    /**
     * Returns true if NFC hardware is available and enabled.
     * <p>
     * This method will always return false if no NFC hardware is available on the device. You can use
     * {@link SecurityKeyManager#isNfcHardwareAvailable()} to check if NFC hardware is available.
     */
    public boolean isNfcEnabled() {
        if (nfcAdapter == null) {
            return false;
        }
        return nfcAdapter.isEnabled();
    }

    /**
     * Returns true if NFC hardware is available and enabled.
     * <p>
     * This is a static variant of {@link #isNfcEnabled()}, it can be used to check if NFC is enabled without creating
     * an instance of NfcStatusObserver. However, in activities that expect NFC interactions, it is generally preferable
     * to handle this dynamically, in case NFC is dynamically enabled or disabled.
     */
    public static boolean isNfcEnabled(Context context) {
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(context);
        return nfcAdapter != null && nfcAdapter.isEnabled();
    }

    public interface NfcStatusCallback {
        /**
         * Called when the NFC device state changes. Note that this callback is only triggered while
         * the NfcStatusObserver is bound to a resumed Lifecycle.
         */
        void onNfcDeviceStateChanged(boolean isEnabled);
    }
}
