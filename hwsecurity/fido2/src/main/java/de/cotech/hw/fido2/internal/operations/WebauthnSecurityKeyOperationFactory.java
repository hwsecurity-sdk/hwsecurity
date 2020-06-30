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

package de.cotech.hw.fido2.internal.operations;


import de.cotech.hw.fido2.PublicKeyCredentialCreate;
import de.cotech.hw.fido2.PublicKeyCredentialGet;
import de.cotech.hw.fido2.internal.cbor.CborPublicKeyCredentialDescriptorParser;
import de.cotech.hw.fido2.internal.json.JsonCollectedClientDataSerializer;
import de.cotech.hw.fido2.internal.operations.ctap1.AuthenticatorGetAssertionCtap1Operation;
import de.cotech.hw.fido2.internal.operations.ctap1.AuthenticatorMakeCredentialCtap1Operation;
import de.cotech.hw.fido2.internal.operations.ctap2.AuthenticatorGetAssertionOperation;
import de.cotech.hw.fido2.internal.operations.ctap2.AuthenticatorMakeCredentialOperation;
import de.cotech.hw.fido2.internal.pinauth.PinProtocolV1;
import de.cotech.hw.fido2.internal.webauthn.ConstructCredentialAlg;
import de.cotech.hw.fido2.internal.webauthn.WebauthnCommand;
import de.cotech.hw.fido2.internal.webauthn.WebauthnResponse;


public class WebauthnSecurityKeyOperationFactory {
    private final PinProtocolV1 pinProtocolV1;
    private static final CborPublicKeyCredentialDescriptorParser
            CBOR_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR_PARSER = new CborPublicKeyCredentialDescriptorParser();
    private static final ConstructCredentialAlg CONSTRUCT_CREDENTIAL_ALG = new ConstructCredentialAlg();
    private static final JsonCollectedClientDataSerializer JSON_COLLECTED_CLIENT_DATA_SERIALIZER =
            new JsonCollectedClientDataSerializer();

    public WebauthnSecurityKeyOperationFactory(PinProtocolV1 pinProtocolV1) {
        this.pinProtocolV1 = pinProtocolV1;
    }


    public <WR extends WebauthnResponse, WC extends WebauthnCommand>
            WebauthnSecurityKeyOperation<WR, WC> getOperation(WC webauthnCommand, boolean isCtap2Supported) {
        if (isCtap2Supported) {
            return getCtap2Operation(webauthnCommand);
        } else {
            return getCtap1Operation(webauthnCommand);
        }
    }

    @SuppressWarnings("unchecked") // we hand out only correctly matching operations
    private <WR extends WebauthnResponse, WC extends WebauthnCommand> WebauthnSecurityKeyOperation<WR, WC> getCtap2Operation(
            WC webauthnCommand) {
        if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            return (WebauthnSecurityKeyOperation<WR, WC>) getAuthenticatorMakeCredentialOperation();
        } else if (webauthnCommand instanceof PublicKeyCredentialGet) {
            return (WebauthnSecurityKeyOperation<WR, WC>) getAuthenticatorGetAssertionOperation();
        } else {
            throw new UnsupportedOperationException();
        }
    }

    @SuppressWarnings("unchecked") // we hand out only correctly matching operations
    private <WR extends WebauthnResponse, WC extends WebauthnCommand> WebauthnSecurityKeyOperation<WR, WC> getCtap1Operation(
            WC webauthnCommand) {
        if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            return (WebauthnSecurityKeyOperation<WR, WC>) new AuthenticatorMakeCredentialCtap1Operation(
                    getAuthenticatorMakeCredentialOperation());
        } else if (webauthnCommand instanceof PublicKeyCredentialGet) {
            return (WebauthnSecurityKeyOperation<WR, WC>) new AuthenticatorGetAssertionCtap1Operation(
                    getAuthenticatorGetAssertionOperation());
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private AuthenticatorMakeCredentialOperation getAuthenticatorMakeCredentialOperation() {
        return new AuthenticatorMakeCredentialOperation(CONSTRUCT_CREDENTIAL_ALG, pinProtocolV1);
    }

    private AuthenticatorGetAssertionOperation getAuthenticatorGetAssertionOperation() {
        return new AuthenticatorGetAssertionOperation(
                CBOR_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR_PARSER, pinProtocolV1,
                JSON_COLLECTED_CLIENT_DATA_SERIALIZER);
    }
}
