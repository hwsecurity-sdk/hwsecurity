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


import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import android.content.Context;
import android.content.SharedPreferences;

import de.cotech.hw.openpgp.pairedkey.PairedSecurityKey;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKeySerializer;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKeySerializerImpl;
import de.cotech.hw.util.Hex;


/**
 * A simple, {@link SharedPreferences} based {@link PairedSecurityKeyStorage}.
 */
public class AndroidPreferencePairedSecurityKeyStorage implements PairedSecurityKeyStorage {
    private static final String PREFS_FILENAME = "paired_hardware.prefs";
    private static final int PREFS_MODE = Context.MODE_PRIVATE;

    private static final String PREF_PREFIX = "paired_key_";

    public static AndroidPreferencePairedSecurityKeyStorage getInstance(Context context) {
        PairedSecurityKeySerializer pairedSecurityKeySerializer = new PairedSecurityKeySerializerImpl();
        return new AndroidPreferencePairedSecurityKeyStorage(context.getSharedPreferences(PREFS_FILENAME, PREFS_MODE),
                pairedSecurityKeySerializer);
    }


    private final SharedPreferences sharedPreferences;
    private final PairedSecurityKeySerializer pairedSecurityKeySerializer;

    private AndroidPreferencePairedSecurityKeyStorage(SharedPreferences sharedPreferences,
                                                      PairedSecurityKeySerializer pairedSecurityKeySerializer) {
        this.sharedPreferences = sharedPreferences;
        this.pairedSecurityKeySerializer = pairedSecurityKeySerializer;
    }

    @Override
    public PairedSecurityKey getPairedSecurityKey(byte[] securityKeyAid) {
        String securityKeyPrefKey = getPrefKeyForSecurityKeyAid(securityKeyAid);
        String serializedPairedSecurityKey = sharedPreferences.getString(securityKeyPrefKey, null);
        if (serializedPairedSecurityKey == null) {
            return null;
        }
        return pairedSecurityKeySerializer.deserialize(serializedPairedSecurityKey);
    }

    @Override
    public Set<PairedSecurityKey> getAllPairedSecurityKeys() {
        Map<String, ?> allEntries = sharedPreferences.getAll();
        if (allEntries == null) {
            return new HashSet<>();
        }

        Set<PairedSecurityKey> allSecurityKeys = new HashSet<>();
        for (Map.Entry<String, ?> entry : allEntries.entrySet()) {
            String serializedPairedSecurityKey = (String) entry.getValue();
            PairedSecurityKey pairedSecurityKey =
                    pairedSecurityKeySerializer.deserialize(serializedPairedSecurityKey);
            allSecurityKeys.add(pairedSecurityKey);
        }
        return allSecurityKeys;
    }

    @Override
    public void addPairedSecurityKey(PairedSecurityKey pairedSecurityKey) {
        String securityKeyPrefKey = getPrefKeyForSecurityKeyAid(pairedSecurityKey.getSecurityKeyAid());
        String serializedSecurityKey = pairedSecurityKeySerializer.serialize(pairedSecurityKey);
        sharedPreferences.edit()
                .putString(securityKeyPrefKey, serializedSecurityKey)
                .apply();
    }

    private String getPrefKeyForSecurityKeyAid(byte[] securityKeyAid) {
        return PREF_PREFIX + Hex.encodeHexString(securityKeyAid);
    }
}