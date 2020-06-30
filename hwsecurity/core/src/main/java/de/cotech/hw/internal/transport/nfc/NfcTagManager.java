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

package de.cotech.hw.internal.transport.nfc;


import java.util.HashMap;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Handler;

import androidx.annotation.AnyThread;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class NfcTagManager {
    private static final long MONITOR_SLEEP_INTERVAL = 250;
    private static final int MONITOR_PING_DELAY = 750;
    private static final int MONITOR_TIMEOUT_DELAY = 20000;

    private final OnDiscoveredNfcTagListener callback;
    private final Handler callbackHandler;
    private final boolean enableDebugLogging;
    private final boolean enablePersistentNfcConnection;

    private final HashMap<Tag, ManagedNfcTag> managedNfcTags = new HashMap<>();

    public static NfcTagManager createInstance(OnDiscoveredNfcTagListener callback,
            Handler handler, boolean enableDebugLogging, boolean enablePersistentNfcConnection) {
        return new NfcTagManager(callback, handler, enableDebugLogging, enablePersistentNfcConnection);
    }

    private NfcTagManager(OnDiscoveredNfcTagListener callback, Handler handler, boolean enableDebugLogging,
            boolean enablePersistentNfcConnection) {
        this.callback = callback;
        this.callbackHandler = handler;
        this.enableDebugLogging = enableDebugLogging;
        this.enablePersistentNfcConnection = enablePersistentNfcConnection;
    }

    @UiThread
    public void onNfcIntent(Intent intent) {
        Tag nfcTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (nfcTag == null) {
            HwTimber.e("Got NFC discovery intent, but missing device extra!");
            HwTimber.e("Intent: %s", intent);
            return;
        }
        initializeNfcTag(nfcTag);
    }

    @UiThread
    void onNfcTag(Tag tag) {
        initializeNfcTag(tag);
    }

    @UiThread
    private void initializeNfcTag(Tag nfcTag) {
        synchronized (managedNfcTags) {
            if (managedNfcTags.containsKey(nfcTag)) {
                HwTimber.d("NFC security key already managed, ignoring (%s)",  getNfcTagIdentifier(nfcTag));
                return;
            }

            ManagedNfcTag managedNfcTag = createManagedNfcTag(nfcTag);
            managedNfcTags.put(nfcTag, managedNfcTag);
        }
    }

    @AnyThread
    private ManagedNfcTag createManagedNfcTag(Tag nfcTag) {
        HwTimber.d("Initializing managed NFC security key");

        ManagedNfcTag managedNfcTag = new ManagedNfcTag(nfcTag);
        managedNfcTag.createNewActiveNfcTransport();
        return managedNfcTag;
    }

    private class ManagedNfcTag {
        private final Tag nfcTag;
        private NfcTransport activeTransport;

        private ManagedNfcTag(Tag nfcTag) {
            this.nfcTag = nfcTag;
        }

        @AnyThread
        synchronized void clearActiveNfcTransport() {
            callbackHandler.post(activeTransport::release);
        }

        @AnyThread
        synchronized void createNewActiveNfcTransport() {
            HwTimber.d("Discovered NFC tag (%s)", getNfcTagIdentifier(nfcTag));

            if (activeTransport != null) {
                HwTimber.d("Tag already connected!");
                return;
            }

            NfcTransport nfcTransport = NfcTransport.createNfcTransport(nfcTag, enableDebugLogging, enablePersistentNfcConnection);
            activeTransport = nfcTransport;
            startMonitorThread(this).start();
            callbackHandler.post(() -> callback.nfcTransportDiscovered(nfcTransport));
        }
    }

    @AnyThread
    private NfcMonitorThread startMonitorThread(ManagedNfcTag managedNfcTag) {
        return new NfcMonitorThread(managedNfcTag);
    }

    @WorkerThread
    private void onNfcTagLost(Tag nfcTag) {
        HwTimber.d("Lost NFC tag");
        synchronized (managedNfcTags) {
            ManagedNfcTag managedNfcTag = managedNfcTags.get(nfcTag);
            if (managedNfcTag == null) {
                HwTimber.d("Tag was dropped before!");
                return;
            }
            managedNfcTag.clearActiveNfcTransport();
            managedNfcTags.remove(nfcTag);
        }
    }

    private class NfcMonitorThread extends Thread {
        final ManagedNfcTag managedNfcTag;

        NfcMonitorThread(ManagedNfcTag managedNfcTag) {
            this.managedNfcTag = managedNfcTag;
        }

        @Override
        @WorkerThread
        public void run() {
            try {
                while (deviceIsStillConnected()) {
                    sleepInterruptibly();
                }
            } finally {
                onNfcTagLost(managedNfcTag.nfcTag);
            }
        }

        @WorkerThread
        boolean deviceIsStillConnected() {
            long lastTransceiveTime = managedNfcTag.activeTransport.getLastTransceiveTime();
            if (enablePersistentNfcConnection) {
                boolean connectionIsActive = lastTransceiveTime + MONITOR_PING_DELAY > System.currentTimeMillis();
                return connectionIsActive || managedNfcTag.activeTransport.ping();
            } else {
                return lastTransceiveTime + MONITOR_TIMEOUT_DELAY > System.currentTimeMillis();
            }
        }

        @WorkerThread
        void sleepInterruptibly() {
            try {
                Thread.sleep(MONITOR_SLEEP_INTERVAL);
            } catch (InterruptedException e) {
                // nvm
            }
        }
    }

    @AnyThread
    private String getNfcTagIdentifier(Tag tag) {
        return Hex.encodeHexString(tag.getId());
    }

    public interface OnDiscoveredNfcTagListener {
        @WorkerThread
        void nfcTransportDiscovered(NfcTransport nfcTransport);
    }
}
