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

package de.cotech.hw.fido2.internal.ctap2.commands.makeCredential;


import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


@AutoValue
public abstract class AuthenticatorMakeCredentialResponse extends Ctap2Response {
    // fmt 	0x01 	text string (CBOR major type 3).
    public abstract String fmt();
    // authData 	0x02 	byte string (CBOR major type 2).
    public abstract byte[] authData();
    // attStmt 	0x03 	definite length map (CBOR major type 5).
    public abstract byte[] attStmt();

    public abstract byte[] clientDataJSON();


    public static AuthenticatorMakeCredentialResponse create(String fmt, byte[] authData, byte[] attStmt, byte[] clientDataJSON) {
        return new AutoValue_AuthenticatorMakeCredentialResponse(fmt, authData, attStmt, clientDataJSON);
    }
}
