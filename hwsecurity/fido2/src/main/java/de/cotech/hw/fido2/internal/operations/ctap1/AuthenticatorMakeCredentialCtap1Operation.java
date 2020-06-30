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

package de.cotech.hw.fido2.internal.operations.ctap1;


import java.io.IOException;

import de.cotech.hw.fido2.internal.cbor.CborCtap1AttestationStatementUtil;
import de.cotech.hw.fido2.internal.cose.CosePublicKeyUtils;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential;
import de.cotech.hw.fido2.domain.create.AttestationObject;
import de.cotech.hw.fido2.domain.create.AttestedCredentialData;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttestationResponse;
import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.PublicKeyCredentialCreate;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.Fido2CommandApduFactory;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.operations.ctap2.AuthenticatorMakeCredentialOperation;
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser;
import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.internal.cbor.CborAttestationObjectSerializer;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HashUtil;


public class AuthenticatorMakeCredentialCtap1Operation extends
        WebauthnSecurityKeyOperation<PublicKeyCredential, PublicKeyCredentialCreate> {
    private final AuthenticatorMakeCredentialOperation ctap2Operation;
    private final Fido2CommandApduFactory fido2CommandApduFactory = new Fido2CommandApduFactory();
    private final AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();

    public AuthenticatorMakeCredentialCtap1Operation(
            AuthenticatorMakeCredentialOperation ctap2Operation) {
        this.ctap2Operation = ctap2Operation;
    }

    @Override
    public PublicKeyCredential performWebauthnSecurityKeyOperation(
            Fido2AppletConnection fido2AppletConnection,
            PublicKeyCredentialCreate create) throws IOException {
        AuthenticatorMakeCredential authenticatorGetAssertion =
                ctap2Operation.webauthnToCtap2Command(create, null);

        byte[] rpIdHash = HashUtil.sha256(authenticatorGetAssertion.rp().id());

        CommandApdu registrationCommand = createCtap1CommandApdu(authenticatorGetAssertion, rpIdHash);
        ResponseApdu responseApdu = fido2AppletConnection.communicateOrThrow(registrationCommand);
        return ctap1ResponseApduToWebauthnResponse(authenticatorGetAssertion, rpIdHash, responseApdu);
    }

    private CommandApdu createCtap1CommandApdu(
            AuthenticatorMakeCredential authenticatorGetAssertion, byte[] rpIdHash) {
        byte[] challengeParam = authenticatorGetAssertion.clientDataHash();
        byte[] payload = Arrays.concatenate(challengeParam, rpIdHash);
        return fido2CommandApduFactory.createRegistrationCommand(payload);
    }

    private PublicKeyCredential ctap1ResponseApduToWebauthnResponse(
            AuthenticatorMakeCredential authenticatorGetAssertion, byte[] applicationParam,
            ResponseApdu responseApdu) throws IOException {
        byte[] responseData = responseApdu.getData();
        U2fRegisterResponse u2fResponse = U2fRegisterResponse.fromBytes(responseData);
        byte[] coseEncodedCredentialPublicKey = CosePublicKeyUtils.encodex962PublicKeyAsCose(u2fResponse.publicKey());
        AttestedCredentialData attestedCredentialData =
                AttestedCredentialData.create(new byte[16], u2fResponse.keyHandle(), coseEncodedCredentialPublicKey);
        byte flags = (byte) (AuthenticatorData.FLAG_USER_PRESENT | AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA);
        AuthenticatorData authenticatorData = AuthenticatorData
                .create(applicationParam, flags, 0, attestedCredentialData, null);
        byte[] authData = authenticatorDataParser.toBytes(authenticatorData);
        byte[] attStmt = CborCtap1AttestationStatementUtil.toAttestionStatement(
                u2fResponse.attestationCertificate(), u2fResponse.signature());

        AttestationObject attestationObject = AttestationObject.create("fido-u2f", authData, attStmt);

        byte[] rawId = authenticatorData.attestedCredentialData().credentialId();
        byte[] attestationObjectBytes = new CborAttestationObjectSerializer().serializeAttestationObject(attestationObject);
        AuthenticatorAttestationResponse response = AuthenticatorAttestationResponse.create(
                authenticatorGetAssertion.clientDataJson().getBytes(), attestationObjectBytes);
        return PublicKeyCredential.create(rawId, response);
    }
}
