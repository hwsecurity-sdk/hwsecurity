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
import android.nfc.NfcAdapter;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.util.HwTimber;


/**
 * A pseudo-activity used in the NFC dispatching process.
 * <p>
 * This class is optional, and shipped as an extra library (see below). If included, NFC security key discovery will
 * work also while the App is not in the foreground. This is strictly optional, NFC dispatch will work with no
 * limitations while the App is in the foreground.
 * <p>
 * This is an internal class used for discovering NFC security keys through the intent dispatch mechanism. It
 * should never be used directly, but automatically supplements the discovery mechanism in {@link SecurityKeyManager}.
 * <p>
 * To include this class, add the following to <code>build.gradle</code>:
 * <p>
 * <code>implementation 'de.cotech:hwsecurity-intent-nfc:1.0'</code>
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public final class NfcIntentDispatchActivity extends Activity {
    SecurityKeyManager securityKeyManager = SecurityKeyManager.getInstance();

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent == null || !NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            return;
        }

        HwTimber.d("Nfc Security Key connected!");
        securityKeyManager.onNfcIntent(intent);
        finish();
    }
}
