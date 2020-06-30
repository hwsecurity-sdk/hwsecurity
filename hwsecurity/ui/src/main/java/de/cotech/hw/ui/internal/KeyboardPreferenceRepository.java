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

package de.cotech.hw.ui.internal;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.RestrictTo;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class KeyboardPreferenceRepository {

    private Context context;

    public KeyboardPreferenceRepository(Context context) {
        this.context = context;
    }

    private static final String PREFERENCES_NAME = "hwsecurity_ui_preferences";
    private static final String PREFERENCES_KEY_KEYBOARD_PREFERRED = "keyboard_preferred";

    public boolean isKeyboardPreferred() {
        SharedPreferences preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (preferences == null) {
            return false;
        }
        return preferences.getBoolean(PREFERENCES_KEY_KEYBOARD_PREFERRED, false);
    }

    public void setIsKeyboardPreferred(boolean isKeyboardPreferred) {
        SharedPreferences preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (preferences == null) {
            return;
        }

        preferences.edit()
                .putBoolean(PREFERENCES_KEY_KEYBOARD_PREFERRED, isKeyboardPreferred)
                .apply();
    }
}
