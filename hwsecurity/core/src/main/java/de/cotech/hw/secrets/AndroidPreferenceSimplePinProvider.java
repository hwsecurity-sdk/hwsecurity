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

package de.cotech.hw.secrets;


import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import de.cotech.hw.util.Hex;


/**
 * A simple, {@link SharedPreferences} based {@link PinProvider} that implicitly generates
 * and stores a PIN per security key.
 */
public class AndroidPreferenceSimplePinProvider implements PinProvider {
    private static final int DEFAULT_PIN_LENGTH = 8;
    private static final String PREFS_FILENAME = "paired_pin.prefs";
    private static final String PREF_PAIRED_PIN = "paired_pin_";
    private static final int PREFS_MODE = Context.MODE_PRIVATE;

    private final ByteSecretGenerator secretGenerator;

    /**
     * Creates an instance of this class.
     *
     * @param prefsFilename The filename to use for the {@link SharedPreferences}.
     */
    public static AndroidPreferenceSimplePinProvider getInstance(Context context, String prefsFilename) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(prefsFilename, PREFS_MODE);
        ByteSecretGenerator secretGenerator = ByteSecretGenerator.getInstance();

        return new AndroidPreferenceSimplePinProvider(sharedPreferences, secretGenerator);
    }

    /**
     * Creates an instance of this class, using the default filename "paired_pin.prefs".
     */
    public static AndroidPreferenceSimplePinProvider getInstance(Context context) {
        return getInstance(context, PREFS_FILENAME);
    }

    private final SharedPreferences sharedPreferences;

    private AndroidPreferenceSimplePinProvider(SharedPreferences sharedPreferences,
                                               ByteSecretGenerator secretGenerator) {
        this.sharedPreferences = sharedPreferences;
        this.secretGenerator = secretGenerator;
    }

    /**
     * Returns a PIN for the security key identified by the given AID.
     * <p>
     * This PIN is retrieved from the preferences storage if it exists, or otherwise generated and stored.
     */
    @Override
    public ByteSecret getPin(byte[] securityKeyIdentifier) {
        String securityKeyPrefName = getSecurityKeyPrefNameForAid(securityKeyIdentifier);

        String pairedPinHex = sharedPreferences.getString(securityKeyPrefName, null);
        if (pairedPinHex != null) {
            return ByteSecret.fromByteArrayAndClear(Hex.decodeHexOrFail(pairedPinHex));
        }

        return generatePin(securityKeyPrefName);
    }

    @Override
    public ByteSecret getPuk(byte[] securityKeyAid) {
        return null;
    }

    /**
     * Clears a paired PIN from the stored SharedPreferences.
     */
    @SuppressLint("ApplySharedPref") // definitely want to delete this info from storage asap
    public void clearPairedPin(byte[] securityKeyIdentifier) {
        String securityKeyPrefName = getSecurityKeyPrefNameForAid(securityKeyIdentifier);

        sharedPreferences.edit().remove(securityKeyPrefName).commit();
    }

    private String getSecurityKeyPrefNameForAid(byte[] securityKeyIdentifier) {
        String securityKeyIdHex = Hex.encodeHexString(securityKeyIdentifier);
        return PREF_PAIRED_PIN + securityKeyIdHex;
    }

    private ByteSecret generatePin(String securityKeyPinKey) {
        ByteSecret pairedPin = secretGenerator.createRandomNumeric(DEFAULT_PIN_LENGTH);

        String pairedPinHex = Hex.encodeHexString(pairedPin.unsafeGetByteCopy());
        sharedPreferences.edit().putString(securityKeyPinKey, pairedPinHex).apply();

        return pairedPin;
    }
}
