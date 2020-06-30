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
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;


@AutoValue
public abstract class AuthenticatorClientPin extends Ctap2Command<AuthenticatorClientPinResponse> {
    private static final byte PIN_PROTOCOL_V1 = 1;
    private static final byte SUBCOMMAND_GET_RETRIES = 1;
    private static final byte SUBCOMMAND_GET_KEY_AGREEMENT = 2;
    private static final byte SUBCOMMAND_SET_PIN = 3;
    private static final byte SUBCOMMAND_CHANGE_PIN = 4;
    private static final byte SUBCOMMAND_GET_PIN_TOKEN = 5;

    // pinProtocol (0x01) 	Unsigned Integer 	Required 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
    public abstract byte pinProtocol();
    // subCommand (0x02) 	Unsigned Integer 	Required 	The authenticator Client PIN sub command currently being requested
    public abstract byte subCommand();
    // keyAgreement (0x03) 	COSE_Key 	Optional 	Public key of platformKeyAgreementKey. The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] keyAgreement();
    // pinAuth (0x04) 	Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret. See Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator for more details.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] pinAuth();
    // newPinEnc (0x05) 	Byte Array 	Optional 	Encrypted new PIN using sharedSecret. Encryption is done over UTF-8 representation of new PIN.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] newPinEnc();
    // pinHashEnc (0x06) 	Byte Array 	Optional 	Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] pinHashEnc();

    public static AuthenticatorClientPin createGetRetries() {
        return new AutoValue_AuthenticatorClientPin(COMMAND_CLIENT_PIN, PIN_PROTOCOL_V1,
                SUBCOMMAND_GET_RETRIES, null, null, null, null);
    }

    public static AuthenticatorClientPin createGetKeyAgreement() {
        return new AutoValue_AuthenticatorClientPin(COMMAND_CLIENT_PIN, PIN_PROTOCOL_V1,
                SUBCOMMAND_GET_KEY_AGREEMENT, null, null, null, null);
    }

    public static AuthenticatorClientPin createGetPinToken(byte[] keyAgreementPlatformPublicKey,
            byte[] pinHashEnc) {
        return new AutoValue_AuthenticatorClientPin(COMMAND_CLIENT_PIN, PIN_PROTOCOL_V1,
                SUBCOMMAND_GET_PIN_TOKEN, keyAgreementPlatformPublicKey, null, null, pinHashEnc);
    }

    @Override
    public Ctap2ResponseFactory<AuthenticatorClientPinResponse> getResponseFactory() {
        return new AuthenticatorClientPinResponseFactory();
    }
}
