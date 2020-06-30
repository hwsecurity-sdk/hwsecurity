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

package de.cotech.hw.openpgp.storage;


import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import de.cotech.hw.util.Hex;


/**
 * A simple, {@link SharedPreferences} based {@link EncryptedSessionStorage}.
 */
public class AndroidPreferencesEncryptedSessionStorage implements EncryptedSessionStorage {
    private static final String PREFS_FILENAME = "enc_session.prefs";
    private static final int PREFS_MODE = Context.MODE_PRIVATE;

    private static final String PREF_PREFIX = "session_secret_";

    public static AndroidPreferencesEncryptedSessionStorage getInstance(Context context) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(PREFS_FILENAME, PREFS_MODE);
        return new AndroidPreferencesEncryptedSessionStorage(sharedPreferences);
    }

    private final SharedPreferences sharedPreferences;

    private AndroidPreferencesEncryptedSessionStorage(SharedPreferences sharedPreferences) {
        this.sharedPreferences = sharedPreferences;
    }


    @NonNull
    @Override
    public byte[] getEncryptedSessionSecret(byte[] securityKeyAid) {
        String prefKey = getPrefKeyForSecurityKeyAid(securityKeyAid);
        String sessionSecretHex = sharedPreferences.getString(prefKey, null);
        if (sessionSecretHex == null) {
            throw new NullPointerException();
        }
        return Hex.decodeHexOrFail(sessionSecretHex);
    }

    @Override
    public boolean hasEncryptedSessionSecret(byte[] securityKeyAid) {
        String prefKey = getPrefKeyForSecurityKeyAid(securityKeyAid);
        return sharedPreferences.contains(prefKey);
    }

    @Override
    public boolean hasAnyEncryptedSessionSecret() {
        return !sharedPreferences.getAll().isEmpty();
    }

    @Override
    public void setEncryptedSessionSecret(byte[] securityKeyAid, byte[] encryptedSessionSecret) {
        String prefKey = getPrefKeyForSecurityKeyAid(securityKeyAid);
        sharedPreferences.edit()
                .putString(prefKey, Hex.encodeHexString(encryptedSessionSecret))
                .apply();
    }

    private String getPrefKeyForSecurityKeyAid(byte[] securityKeyAid) {
        return PREF_PREFIX + Hex.encodeHexString(securityKeyAid);
    }
}
