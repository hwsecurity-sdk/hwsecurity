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

import java.io.IOException;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.UiThread;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.secrets.PinProvider;

public interface SecurityKeyDialogInterface {
    void cancel();

    void dismiss();

    @AnyThread
    void postError(IOException exception);

    @AnyThread
    void postProgressMessage(String message);

    interface SecurityKeyDialogCallback<T extends SecurityKey> {
        /**
         * IOExceptions are handled by the SecurityKeyDialogFragment if thrown inside this callback.
         */
        @UiThread
        void onSecurityKeyDialogDiscovered(@NonNull SecurityKeyDialogInterface dialogInterface,
                                           @NonNull T securityKey, @Nullable PinProvider pinProvider) throws IOException;

        @UiThread
        default void onSecurityKeyDialogCancel() {
        }

        @UiThread
        default void onSecurityKeyDialogDismiss() {
        }
    }

}
