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

package de.cotech.hw.fido2.internal.webauthn;


import java.io.IOException;

import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.domain.create.AttestationObject;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttestationResponse;
import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.domain.create.CredentialCreationData;
import de.cotech.hw.fido2.internal.cbor.CborAttestationObjectSerializer;
import de.cotech.hw.fido2.internal.cbor.CborConstants;
import de.cotech.hw.util.HwTimber;


public class ConstructCredentialAlg {
    private static CborAttestationObjectSerializer
            cborAttestationObjectSerializer = new CborAttestationObjectSerializer();
    private static AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();

    public PublicKeyCredential publicKeyCredential(CredentialCreationData credentialCreationData)
            throws IOException {
        switch (credentialCreationData.attestationConveyancePreferenceOption()) {
            case NONE:
                return none(credentialCreationData);
            case INDIRECT:
                HwTimber.e("Attestation method 'indirect' is not supported. Falling back to 'none'.");
                return none(credentialCreationData);
            case DIRECT:
                return direct(credentialCreationData);
        }
        throw new UnsupportedOperationException();
    }

    private PublicKeyCredential none(CredentialCreationData credentialCreationData)
            throws IOException {
        AttestationObject anonymizedMakeCredentialResponse =
                createAnonymizedMakeCredentialResponse(credentialCreationData);

        byte[] rawId = findRawIdFromMakeCredentialResponse(anonymizedMakeCredentialResponse);
        AuthenticatorAttestationResponse response = createAuthenticatorAttestationResponse(
                anonymizedMakeCredentialResponse, credentialCreationData.clientDataJSONResult());

        return PublicKeyCredential.create(rawId, response);
    }

    private AuthenticatorAttestationResponse createAuthenticatorAttestationResponse(
            AttestationObject makeCredentialResponse,
            byte[] clientDataJSONResult
    ) throws IOException {
        byte[] anonymizedAttestationObject =
                cborAttestationObjectSerializer.serializeAttestationObject(makeCredentialResponse);
        return AuthenticatorAttestationResponse
                .create(clientDataJSONResult, anonymizedAttestationObject);
    }

    private byte[] findRawIdFromMakeCredentialResponse(
            AttestationObject makeCredentialResponse) throws IOException {
        AuthenticatorData authenticatorData = authenticatorDataParser.fromBytes(makeCredentialResponse.authData());
        return authenticatorData.attestedCredentialData().credentialId();
    }

    private AttestationObject createAnonymizedMakeCredentialResponse(
            CredentialCreationData credentialCreationData
    ) throws IOException {
        AuthenticatorData authenticatorData = authenticatorDataParser
                .fromBytes(credentialCreationData.attestationObjectResult().authData())
                .withEmptyAaguid();
        byte[] anonymizedAuthenticatorData = authenticatorDataParser.toBytes(authenticatorData);

        return AttestationObject.create(
                "none", anonymizedAuthenticatorData, CborConstants.EMPTY_MAP_BYTES);
    }

    private PublicKeyCredential direct(CredentialCreationData credentialCreationData)
            throws IOException {
        AttestationObject attestationObject = credentialCreationData.attestationObjectResult();
        byte[] rawId = getRawIdFromAuthenticatorAttestationResponse(attestationObject);
        byte[] attestationObjectBytes = new CborAttestationObjectSerializer().serializeAttestationObject(attestationObject);
        AuthenticatorAttestationResponse response = AuthenticatorAttestationResponse.create(
                credentialCreationData.clientDataJSONResult(), attestationObjectBytes);
        return PublicKeyCredential.create(rawId, response);
    }

    private static byte[] getRawIdFromAuthenticatorAttestationResponse(AttestationObject attestationObject)
            throws IOException {
        AuthenticatorData authenticatorData = authenticatorDataParser.fromBytes(attestationObject.authData());
        return authenticatorData.attestedCredentialData().credentialId();
    }
}
