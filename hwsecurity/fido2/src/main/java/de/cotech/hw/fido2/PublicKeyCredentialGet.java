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

package de.cotech.hw.fido2;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.internal.webauthn.WebauthnCommand;


@AutoValue
public abstract class PublicKeyCredentialGet extends WebauthnCommand {
    public abstract String origin();
    public abstract PublicKeyCredentialRequestOptions options();
    @Nullable
    public abstract String clientPin();
    public abstract boolean lastAttemptOk();

    public static PublicKeyCredentialGet create(String origin, PublicKeyCredentialRequestOptions options) {
        return new AutoValue_PublicKeyCredentialGet(origin, options, null, false);
    }

    @Override
    public PublicKeyCredentialGet withClientPin(String clientPin, boolean lastAttemptOk) {
        return new AutoValue_PublicKeyCredentialGet(origin(), options(), clientPin, lastAttemptOk);
    }
}
