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

package de.cotech.hw.fido2.domain.get;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;


@AutoValue
public abstract class AssertionCreationData {
    public abstract byte[] credentialIdResult();
    public abstract byte[] clientDataJSONResult();
    public abstract byte[] authenticatorDataResult();
    public abstract byte[] signatureResult();
    @Nullable
    public abstract byte[] userHandleResult();

    public static AssertionCreationData create(byte[] credentialId, byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, @Nullable byte[] userHandle) {
        return new AutoValue_AssertionCreationData(credentialId, clientDataJSON, authenticatorData, signature, userHandle);
    }
}
