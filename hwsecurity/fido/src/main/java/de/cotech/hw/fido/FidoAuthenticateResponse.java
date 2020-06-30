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

package de.cotech.hw.fido;


import android.os.Parcelable;

import com.google.auto.value.AutoValue;
import androidx.annotation.Nullable;


@AutoValue
public abstract class FidoAuthenticateResponse {
    public abstract String getClientData();
    @SuppressWarnings("mutable")
    public abstract byte[] getKeyHandle();
    @SuppressWarnings("mutable")
    public abstract byte[] getBytes();
    @Nullable
    public abstract Parcelable getCustomDataParcelable();

    public <T extends Parcelable> T getCustomData() {
        // noinspection unchecked
        return (T) getCustomDataParcelable();
    }

    public static FidoAuthenticateResponse create(String clientData, byte[] keyHandle, byte[] signature, Parcelable customData) {
        return new AutoValue_FidoAuthenticateResponse(clientData, keyHandle, signature, customData);
    }
}