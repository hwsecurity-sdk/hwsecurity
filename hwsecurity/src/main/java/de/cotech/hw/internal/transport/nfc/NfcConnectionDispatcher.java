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

package de.cotech.hw.internal.transport.nfc;


import android.annotation.TargetApi;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;

import androidx.annotation.AnyThread;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import de.cotech.hw.util.Hex;
import timber.log.Timber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class NfcConnectionDispatcher {
    private static final int NFC_IGNORE_DEBOUNCE_MS = 1500;

    private final Activity activity;
    @Nullable
    private final NfcAdapter nfcAdapter;
    private final NfcTagManager nfcTagManager;
    private final boolean disableNfcDiscoverySound;

    public NfcConnectionDispatcher(Activity activity, NfcTagManager nfcTagManager, boolean disableNfcDiscoverySound) {
        this.activity = activity;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
        this.nfcTagManager = nfcTagManager;
        this.disableNfcDiscoverySound = disableNfcDiscoverySound;
    }

    @UiThread
    public void onResume() {
        enableExclusiveNfc();
    }

    @UiThread
    public void onPause() {
        disableExclusiveNfc();
    }

    @UiThread
    @TargetApi(VERSION_CODES.KITKAT)
    private void enableExclusiveNfc() {
        if (nfcAdapter == null) {
            return;
        }
        if (!nfcAdapter.isEnabled()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            enableReaderMode();
        } else {
            enableForegroundDispatch();
        }
    }

    @UiThread
    @TargetApi(Build.VERSION_CODES.KITKAT)
    private void disableExclusiveNfc() {
        if (nfcAdapter == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            disableReaderMode();
        } else {
            disableForegroundDispatch();
        }
    }

    @UiThread
    @TargetApi(VERSION_CODES.KITKAT)
    private void enableReaderMode() {
        if (nfcAdapter == null) {
            throw new IllegalStateException("Method must not be called if nfcAdapter is null!");
        }
        int flags = NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
        if (disableNfcDiscoverySound) {
            flags |= NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS;
        }
        nfcAdapter.enableReaderMode(activity, nfcTagManager::onNfcTag, flags, null);
    }

    @UiThread
    @TargetApi(VERSION_CODES.KITKAT)
    private void disableReaderMode() {
        if (nfcAdapter == null) {
            throw new IllegalStateException("Method must not be called if nfcAdapter is null!");
        }
        nfcAdapter.disableReaderMode(activity);
    }

    @UiThread
    private void enableForegroundDispatch() {
        if (nfcAdapter == null) {
            throw new IllegalStateException("Method must not be called if nfcAdapter is null!");
        }
        Intent intent = new Intent(activity, activity.getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent tagIntent = PendingIntent.getActivity(activity, 0, intent, PendingIntent.FLAG_CANCEL_CURRENT);
        IntentFilter tag = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        nfcAdapter.enableForegroundDispatch(activity, tagIntent, new IntentFilter[] { tag },
                new String[][] { new String[] { IsoDep.class.getName() } });
    }

    @UiThread
    private void disableForegroundDispatch() {
        if (nfcAdapter == null) {
            throw new IllegalStateException("Method must not be called if nfcAdapter is null!");
        }
        nfcAdapter.disableForegroundDispatch(activity);
    }

    @AnyThread
    public static boolean isNfcHardwareAvailable(Context context) {
        return NfcAdapter.getDefaultAdapter(context) != null;
    }

    @AnyThread
    public void ignoreNfcTag(Tag nfcTag) {
        if (VERSION.SDK_INT >= VERSION_CODES.N) {
            if (nfcAdapter != null) {
                Timber.d("Debouncing NFC tag %s for %dms", Hex.encodeHexString(nfcTag.getId()), NFC_IGNORE_DEBOUNCE_MS);
                nfcAdapter.ignore(nfcTag, NFC_IGNORE_DEBOUNCE_MS, null, null);
            }
        }
    }
}
