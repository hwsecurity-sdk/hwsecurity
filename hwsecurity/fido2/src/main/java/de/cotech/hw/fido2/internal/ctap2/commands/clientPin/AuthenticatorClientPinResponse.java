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

package de.cotech.hw.fido2.internal.ctap2.commands.clientPin;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


@AutoValue
public abstract class AuthenticatorClientPinResponse extends Ctap2Response {
    // KeyAgreement (0x01) 	COSE_Key 	Optional 	Authenticator key agreement public key in COSE_Key format. This will be used to establish a sharedSecret between platform and the authenticator. The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    @Nullable
    public abstract byte[] keyAgreement();
    // pinToken (0x02) 	Byte Array 	Optional 	Encrypted pinToken using sharedSecret to be used in subsequent authenticatorMakeCredential and authenticatorGetAssertion operations.
    @Nullable
    public abstract byte[] pinToken();
    // retries (0x03) 	Unsigned Integer 	Optional 	Number of PIN attempts remaining before lockout. This is optionally used to show in UI when collecting the PIN in Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator flows.
    @Nullable
    public abstract Integer retries();

    public static AuthenticatorClientPinResponse create(
            @Nullable byte[] keyAgreement,
            @Nullable byte[] pinToken,
            @Nullable Integer retries
    ) {
        return new AutoValue_AuthenticatorClientPinResponse(keyAgreement, pinToken, retries);
    }
}
