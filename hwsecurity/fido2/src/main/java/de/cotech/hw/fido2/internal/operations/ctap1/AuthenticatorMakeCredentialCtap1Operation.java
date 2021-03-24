/*
 * Copyright (C) 2018-2021 Confidential Technologies GmbH
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
import java.util.List;
import java.util.Map;

import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.PublicKeyCredentialCreate;
import de.cotech.hw.fido2.domain.PublicKeyCredentialParameters;
import de.cotech.hw.fido2.domain.PublicKeyCredentialType;
import de.cotech.hw.fido2.domain.create.AttestationConveyancePreference;
import de.cotech.hw.fido2.domain.create.AttestationObject;
import de.cotech.hw.fido2.domain.create.AttestedCredentialData;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttestationResponse;
import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.fido2.internal.Fido2CommandApduFactory;
import de.cotech.hw.fido2.internal.cbor.CborAttestationObjectSerializer;
import de.cotech.hw.fido2.internal.cbor.CborCtap1AttestationStatementUtil;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;
import de.cotech.hw.fido2.internal.cose.CosePublicKeyUtils;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperation;
import de.cotech.hw.fido2.internal.operations.ctap2.AuthenticatorMakeCredentialOperation;
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HashUtil;
import de.cotech.hw.util.HwTimber;


public class AuthenticatorMakeCredentialCtap1Operation extends
        WebauthnSecurityKeyOperation<PublicKeyCredential, PublicKeyCredentialCreate> {
    private static final CoseAlg COSE_ALG_FALLBACK = CoseAlg.ES256;

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
        AuthenticatorMakeCredential authenticatorMakeCredential =
                ctap2Operation.webauthnToCtap2Command(create, null);

        byte[] rpIdHash = HashUtil.sha256(authenticatorMakeCredential.rp().id());

        CommandApdu registrationCommand = createCtap1CommandApdu(authenticatorMakeCredential, rpIdHash);
        ResponseApdu responseApdu = fido2AppletConnection.communicateOrThrow(registrationCommand);
        return ctap1ResponseApduToWebauthnResponse(authenticatorMakeCredential, rpIdHash, create.options().attestation(), responseApdu);
    }

    private CommandApdu createCtap1CommandApdu(
            AuthenticatorMakeCredential authenticatorMakeCredential, byte[] rpIdHash) {
        byte[] challengeParam = authenticatorMakeCredential.clientDataHash();
        byte[] payload = Arrays.concatenate(challengeParam, rpIdHash);
        return fido2CommandApduFactory.createRegistrationCommand(payload);
    }

    private PublicKeyCredential ctap1ResponseApduToWebauthnResponse(
            AuthenticatorMakeCredential authenticatorMakeCredential, byte[] applicationParam,
            AttestationConveyancePreference attestationPreference,
            ResponseApdu responseApdu) throws IOException {
        byte[] responseData = responseApdu.getData();
        U2fRegisterResponse u2fResponse = U2fRegisterResponse.fromBytes(responseData);
        CoseAlg coseAlg = findPublicKeyAlgorithm(authenticatorMakeCredential.pubKeyCredParams());
        byte[] coseEncodedCredentialPublicKey = CosePublicKeyUtils.encodex962PublicKeyAsCose(u2fResponse.publicKey(), coseAlg);

        AttestedCredentialData attestedCredentialData =
                AttestedCredentialData.create(new byte[16], u2fResponse.keyHandle(), coseEncodedCredentialPublicKey);
        byte flags = (byte) (AuthenticatorData.FLAG_USER_PRESENT | AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA);
        AuthenticatorData authenticatorData = AuthenticatorData
                .create(applicationParam, flags, 0, attestedCredentialData, null);

        AttestationObject attestationObject = createAttestationObject(attestationPreference, authenticatorData, u2fResponse);

        byte[] rawId = authenticatorData.attestedCredentialData().credentialId();
        byte[] attestationObjectBytes = new CborAttestationObjectSerializer().serializeAttestationObject(attestationObject);
        AuthenticatorAttestationResponse response = AuthenticatorAttestationResponse.create(
                authenticatorMakeCredential.clientDataJson().getBytes(), attestationObjectBytes);
        return PublicKeyCredential.create(rawId, response);
    }

    private AttestationObject createAttestationObject(
            AttestationConveyancePreference attestationPreference,
            AuthenticatorData authenticatorData, U2fRegisterResponse u2fResponse) {
        byte[] authData = authenticatorDataParser.toBytes(authenticatorData);
        AttestationObject attestationObject;
        if (attestationPreference == AttestationConveyancePreference.DIRECT) {
            byte[] attStmt = CborCtap1AttestationStatementUtil.toAttestionStatement(
                    u2fResponse.attestationCertificate(), u2fResponse.signature());
            attestationObject = AttestationObject.create("fido-u2f", authData, attStmt);
        } else {
            byte[] attStmt = CborCtap1AttestationStatementUtil.emptyAttestationStatement();
            attestationObject = AttestationObject.create("none", authData, attStmt);
        }
        return attestationObject;
    }

    private CoseAlg findPublicKeyAlgorithm(List<PublicKeyCredentialParameters> publicKeyCredentialParameters) {
        if (publicKeyCredentialParameters.size() == 0) {
            HwTimber.e("Malformed MakeCredential request: Missing pubKeyCredParams. Assuming public-key type with ES256 algorithm.");
            return COSE_ALG_FALLBACK;
        }
        Map<PublicKeyCredentialType, CoseAlg> params = publicKeyCredentialParameters.get(0).parameters();
        if (!params.containsKey(PublicKeyCredentialType.PUBLIC_KEY)) {
            HwTimber.e("Malformed MakeCredential request: Missing public-key param in pubKeyCredParams. Assuming public-key type with ES256 algorithm.");
            return COSE_ALG_FALLBACK;
        }
        return params.get(PublicKeyCredentialType.PUBLIC_KEY);
    }
}
