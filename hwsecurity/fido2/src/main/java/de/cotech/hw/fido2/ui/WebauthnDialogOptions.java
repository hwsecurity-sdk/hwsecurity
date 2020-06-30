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

package de.cotech.hw.fido2.ui;

import android.os.Parcelable;

import androidx.annotation.Nullable;
import androidx.annotation.StyleRes;

import com.google.auto.value.AutoValue;

import de.cotech.hw.ui.R;

@AutoValue
public abstract class WebauthnDialogOptions implements Parcelable {

    public enum FormFactor {
        SECURITY_KEY,
        SMART_CARD
    }

    @Nullable
    public abstract String getTitle();

    @Nullable
    public abstract Long getTimeoutMs();

    public abstract boolean getPreventScreenshots();

    @StyleRes
    public abstract int getTheme();

    public abstract boolean isForceU2f();

    public abstract FormFactor getFormFactor();

    public abstract boolean getAllowKeyboard();

    public abstract boolean getAllowSkipPin();

    public abstract boolean getShowSdkLogo();

    // default values
    public static Builder builder() {
        return new AutoValue_WebauthnDialogOptions.Builder()
                .setPreventScreenshots(false)
                .setForceU2f(false)
                .setAllowKeyboard(false)
                .setAllowSkipPin(false)
                .setShowSdkLogo(false)
                .setFormFactor(FormFactor.SECURITY_KEY)
                .setTheme(R.style.HwSecurity_Dialog);
    }

    @AutoValue.Builder
    public abstract static class Builder {
        /**
         * Title shown inside the dialog
         * <p>
         * Default: "Register your Security Key" or "Login with your Security Key"
         */
        public abstract Builder setTitle(String title);

        /**
         * Automatically aborts the authentication after a certain time.
         * For native Android apps, we do not recommend setting a timeout.
         * <p>
         * Default: No timeout
         */
        public abstract Builder setTimeoutMs(Long timeoutMs);

        /**
         * Sets FLAG_SECURE on the dialog fragment.
         * <p>
         * This sets the content of the window as 'secure', preventing it from appearing in screenshots,
         * screen recordings or from being viewed on non-secure displays.
         * <p>
         * Default: false
         */
        public abstract Builder setPreventScreenshots(boolean preventScreenshots);

        /**
         * Set your own custom theme for the dialog to change colors:
         * <pre>{@code
         * <style name="MyCustomDialog" parent="HwSecurity.Dialog">
         *     <item name="hwSecurityButtonColor">@color/hwSecurityDarkBlue</item>
         *     <item name="hwSecuritySurfaceColor">@color/hwSecurityBlue</item>
         *     <item name="hwSecurityErrorColor">@color/hwSecurityRed</item>
         * </style>
         * }</pre>
         */
        public abstract Builder setTheme(@StyleRes int theme);

        public abstract Builder setForceU2f(boolean forceU2f);

        /**
         * Option to choose the form factor displayed after the PIN input.
         * <p>
         * Default: SECURITY_KEY
         */
        public abstract Builder setFormFactor(FormFactor formFactor);

        /**
         * Shows a button to switch between numeric keypad and full soft-keyboard.
         * <p>
         * Default: false
         */
        public abstract Builder setAllowKeyboard(boolean allowKeyboard);

        /**
         * Shows a button to that allows to skip the PIN input when RP sets
         * UserVerificationRequirement to "preferred"
         * <p>
         * Default: false
         */
        public abstract Builder setAllowSkipPin(boolean allowSkipPin);

        /**
         * Shows the Hardware Security SDK Logo with a clickable link
         * <p>
         * Default: false
         */
        public abstract Builder setShowSdkLogo(boolean showLogo);

        public abstract WebauthnDialogOptions build();
    }

}
