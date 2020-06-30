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

package de.cotech.hw.ui;

import android.os.Parcelable;

import androidx.annotation.Nullable;
import androidx.annotation.StyleRes;

import com.google.auto.value.AutoValue;

import de.cotech.hw.ui.internal.KeypadPinInput;

@AutoValue
public abstract class SecurityKeyDialogOptions implements Parcelable {

    public enum PinMode {
        PIN_INPUT,
        NO_PIN_INPUT,
        RESET_PIN,
        SETUP
    }

    public enum FormFactor {
        SECURITY_KEY,
        SMART_CARD
    }

    @Nullable
    public abstract String getTitle();

    @Nullable
    public abstract Integer getPinLength();

    @Nullable
    public abstract Integer getPukLength();

    public abstract boolean getPreventScreenshots();

    public abstract boolean getShowReset();

    public abstract PinMode getPinMode();

    public abstract FormFactor getFormFactor();

    public abstract boolean getAllowKeyboard();

    @StyleRes
    public abstract int getTheme();

    public abstract boolean getShowSdkLogo();

    public static Builder builder() {
        return new AutoValue_SecurityKeyDialogOptions.Builder()
                .setPreventScreenshots(true)
                .setShowReset(false)
                .setAllowKeyboard(false)
                .setShowSdkLogo(false)
                .setPinMode(PinMode.PIN_INPUT)
                .setFormFactor(FormFactor.SECURITY_KEY)
                .setTheme(R.style.HwSecurity_Dialog);
    }

    @AutoValue.Builder
    public abstract static class Builder {
        /**
         * Title shown inside the dialog
         * <p>
         * Default: For PinMode.PIN_INPUT: "Login with Security Key"
         */
        public abstract Builder setTitle(String title);

        /**
         * Setting a PIN length hides the "confirm PIN" (checkmark) button from the PIN input step.
         * Instead, the PIN is automatically used when the correct length has been entered.
         * <p>
         * In a controlled deployment of security keys, a fixed PIN length
         * can improve the user experience.
         */
        public abstract Builder setPinLength(Integer pinLength);

        /**
         * Same as PIN length. Only relevant for the reset flow.
         */
        public abstract Builder setPukLength(Integer pukLength);

        /**
         * Sets FLAG_SECURE on the dialog fragment.
         * <p>
         * This sets the content of the window as 'secure', preventing it from appearing in screenshots,
         * screen recordings or from being viewed on non-secure displays.
         * <p>
         * Default: true
         */
        public abstract Builder setPreventScreenshots(boolean preventScreenshots);

        /**
         * Shows a button that allows the reset flow using the PUK.
         * This allows the user to set a new PIN if the security key is blocked after 3 failed PIN attempts.
         * <p>
         * Default: false
         */
        public abstract Builder setShowReset(boolean showReset);

        /**
         * By default a PIN input is shown as most operations require a PIN authentication.
         * For other operations NO_PIN_INPUT can be chosen.
         * <p>
         * Default: PIN_INPUT
         */
        public abstract Builder setPinMode(PinMode pinMode);

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

        /**
         * Shows the Hardware Security SDK Logo with a clickable link
         * <p>
         * Default: false
         */
        public abstract Builder setShowSdkLogo(boolean showLogo);

        abstract SecurityKeyDialogOptions autoBuild();

        public SecurityKeyDialogOptions build() {
            SecurityKeyDialogOptions options = autoBuild();

            if ((options.getPinLength() == null && options.getPukLength() != null)
                    || (options.getPinLength() != null && options.getPukLength() == null)) {
                throw new IllegalArgumentException("When using a fixed PIN length, you must also set a fixed PUK length.");
            }
            if (options.getPinLength() != null && options.getPinLength() > KeypadPinInput.PIN_MAX_DISPLAY_LENGTH) {
                throw new IllegalArgumentException("PIN length > 10 not possible.");
            }
            if (options.getPukLength() != null && options.getPukLength() > KeypadPinInput.PIN_MAX_DISPLAY_LENGTH) {
                throw new IllegalArgumentException("PIN length > 10 not possible.");
            }

            return options;
        }
    }

}
