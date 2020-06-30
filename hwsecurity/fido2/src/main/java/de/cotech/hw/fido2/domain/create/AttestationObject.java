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

package de.cotech.hw.fido2.domain.create;


import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


@AutoValue
public abstract class AttestationObject extends Ctap2Response {
    // fmt 	String 	Required 	The attestation statement format identifier.
    public abstract String fmt();
    // authData 	Byte Array 	Required 	The authenticator data object.
    public abstract byte[] authData();
    // attStmt 	Byte Array, the structure of which depends on the attestation statement format identifier 	Required 	The attestation statement, whose format is identified by the "fmt" object member. The client treats it as an opaque object.     abstract List<String> versions();
    public abstract byte[] attStmt();


    public static AttestationObject create(String fmt, byte[] authData, byte[] attStmt) {
        return new AutoValue_AttestationObject(fmt, authData, attStmt);
    }
}
