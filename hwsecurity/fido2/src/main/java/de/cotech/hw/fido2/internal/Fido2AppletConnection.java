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

package de.cotech.hw.fido2.internal;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.AppletFileNotFoundException;
import de.cotech.hw.exceptions.ClaNotSupportedException;
import de.cotech.hw.exceptions.InsNotSupportedException;
import de.cotech.hw.exceptions.SelectAppletException;
import de.cotech.hw.exceptions.WrongRequestLengthException;
import de.cotech.hw.fido2.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido2.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Command;
import de.cotech.hw.fido2.internal.ctap2.Ctap2CommandApduTransformer;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Exception;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;
import de.cotech.hw.fido2.internal.ctap2.CtapErrorResponse;
import de.cotech.hw.fido2.internal.ctap2.commands.getInfo.AuthenticatorGetInfo;
import de.cotech.hw.fido2.internal.ctap2.commands.getInfo.AuthenticatorGetInfoResponse;
import de.cotech.hw.fido2.internal.pinauth.PinToken;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class Fido2AppletConnection {
    private static final int APDU_SW1_RESPONSE_AVAILABLE = 0x61;
    private static final int RESPONSE_SW1_INCORRECT_LENGTH = 0x6C;

    private static final List<byte[]> FIDO_AID_PREFIXES = Arrays.asList(
            // see to "FIDO U2F NFC protocol", Section 5. Applet selection
            // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html
            Hex.decodeHexOrFail("A0000006472F0001"),
            // Workaround for Solokey for firmware < 2.4.0: https://github.com/solokeys/solo/issues/213
            Hex.decodeHexOrFail("A0000006472F000100"),
            // old Yubico demo applet AID
            Hex.decodeHexOrFail("A0000005271002")
    );

    @NonNull
    private final Transport transport;
    @NonNull
    private final Fido2CommandApduFactory commandFactory;
    @NonNull
    private final Ctap2CommandApduTransformer ctap2CommandApduTransformer;

    private boolean isFidoAppletConnected;
    private AuthenticatorGetInfoResponse ctap2Info;
    private boolean isForceCtap1;

    private PinToken cachedPinToken;

    public static Fido2AppletConnection getInstanceForTransport(@NonNull Transport transport) {
        return new Fido2AppletConnection(transport, new Fido2CommandApduFactory(), new Ctap2CommandApduTransformer());
    }

    private Fido2AppletConnection(@NonNull Transport transport, @NonNull Fido2CommandApduFactory commandFactory,
            @NonNull Ctap2CommandApduTransformer ctap2CommandApduTransformer) {
        this.transport = transport;
        this.commandFactory = commandFactory;
        this.ctap2CommandApduTransformer = ctap2CommandApduTransformer;
    }

    // region connection management

    public void connectIfNecessary() throws IOException {
        if (isFidoAppletConnected) {
            return;
        }

        connectToDevice();
    }

    private void connectToDevice() throws IOException {
        try {
            if (transport.getTransportType() == TransportType.USB_CTAPHID) {
                HwTimber.d("Using USB U2F HID as a transport. No need to select AID.");
                byte[] versionBytes = readVersion();
                checkVersionOrThrow(versionBytes);
            } else {
                byte[] selectedAid = selectFilesFromPrefixOrFail();
                HwTimber.d("Connected to AID %s", Hex.encodeHexString(selectedAid));
            }

            try {
                ctap2Info = ctap2AuthenticatorGetInfo();
                HwTimber.d("Call to AuthenticatorGetInfo returns valid response - using CTAP2");
                HwTimber.d(ctap2Info.toString());
            } catch (IOException e) {
                HwTimber.d("Call to AuthenticatorGetInfo returned no valid response - using CTAP1");
            }

            isFidoAppletConnected = true;
        } catch (IOException e) {
            transport.release();
            throw e;
        }
    }

    private AuthenticatorGetInfoResponse ctap2AuthenticatorGetInfo() throws IOException {
        return ctap2CommunicateOrThrow(AuthenticatorGetInfo.create());
    }

    public <T extends Ctap2Response> T ctap2CommunicateOrThrow(Ctap2Command<T> ctap2Command)
            throws IOException {
        if (!isCtap2Capable()) {
            HwTimber.w("Attempting to send CTAP2 command, but CTAP2 is not supported. " +
                    "This will probably cause an error.");
        }
        CommandApdu commandApdu = ctap2CommandApduTransformer.toCommandApdu(ctap2Command);
        ResponseApdu responseApdu = communicateOrThrow(commandApdu);
        Ctap2Response ctap2Response = ctap2ResponseFromResponseApdu(ctap2Command, responseApdu);
        // noinspection unchecked, this is ensured in Ctap2ResponseTransformer
        return (T) ctap2Response;
    }

    private Ctap2Response ctap2ResponseFromResponseApdu(Ctap2Command command, ResponseApdu responseApdu)
            throws IOException {
        byte[] data = responseApdu.getData();
        if (data[0] != CtapErrorResponse.CTAP2_OK) {
            throw new Ctap2Exception(CtapErrorResponse.create(data[0]));
        }

        byte[] responseData = de.cotech.hw.util.Arrays.copyOfRange(data, 1, data.length);
        return command.getResponseFactory().createResponse(responseData);
    }

    private byte[] selectFilesFromPrefixOrFail() throws IOException {
        for (byte[] fileAid : FIDO_AID_PREFIXES) {
            byte[] initializedAid = selectFileOrFail(fileAid);
            if (initializedAid != null) {
                return initializedAid;
            }
        }
        throw new SelectAppletException(FIDO_AID_PREFIXES, "FIDO U2F or CTAP2");
    }

    private void checkVersionOrThrow(byte[] versionBytes) throws IOException {
        String version = new String(versionBytes, Charset.forName("ASCII"));

        if ("U2F_V2".equals(version) || "FIDO_2_0".equals(version)) {
            HwTimber.d("U2F applet answered correctly with version U2F_V2 or FIDO_2_0");
        } else {
            HwTimber.e("Applet did NOT answer with a correct version string!");
            throw new IOException("Applet replied with incorrect version string!");
        }
    }

    private byte[] selectFileOrFail(byte[] fileAid) throws IOException {
        CommandApdu select = commandFactory.createSelectFileCommand(fileAid);

        try {
            ResponseApdu response = communicateOrThrow(select);

            // "FIDO authenticator SHALL reply with its version string in the successful response"
            // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html
            checkVersionOrThrow(response.getData());
            return fileAid;
        } catch (AppletFileNotFoundException e) {
            return null;
        }
    }

    // endregion

    // region communication

    // see "FIDO U2F Raw Message Formats", Section 3.3 Status Codes
    // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
    public ResponseApdu communicateOrThrow(CommandApdu commandApdu) throws IOException {
        ResponseApdu response = communicate(commandApdu);

        if (response.isSuccess()) {
            return response;
        }

        switch (response.getSw()) {
            case FidoPresenceRequiredException.SW_TEST_OF_USER_PRESENCE_REQUIRED:
                throw new FidoPresenceRequiredException();
            case FidoWrongKeyHandleException.SW_WRONG_KEY_HANDLE:
                throw new FidoWrongKeyHandleException();
            case AppletFileNotFoundException.SW_FILE_NOT_FOUND:
                throw new AppletFileNotFoundException();
            case ClaNotSupportedException.SW_CLA_NOT_SUPPORTED:
                throw new ClaNotSupportedException();
            case InsNotSupportedException.SW_INS_NOT_SUPPORTED:
                throw new InsNotSupportedException();
            case WrongRequestLengthException.SW_WRONG_REQUEST_LENGTH:
                throw new WrongRequestLengthException();
            default:
                throw new SecurityKeyException("UNKNOWN", response.getSw());
        }
    }

    // ISO/IEC 7816-4
    private ResponseApdu communicate(CommandApdu commandApdu) throws IOException {
        ResponseApdu lastResponse;

        lastResponse = sendWithChaining(commandApdu);
        if (lastResponse.getSw1() == RESPONSE_SW1_INCORRECT_LENGTH && lastResponse.getSw2() != 0) {
            commandApdu = commandApdu.withNe(lastResponse.getSw2());
            lastResponse = sendWithChaining(commandApdu);
        }
        lastResponse = readChainedResponseIfAvailable(lastResponse);

        return lastResponse;
    }

    // ISO/IEC 7816-4
    @NonNull
    private ResponseApdu sendWithChaining(CommandApdu commandApdu) throws IOException {
        /* CTAP2 Spec:
         * "If the request was encoded using extended length APDU encoding,
         * the authenticator MUST respond using the extended length APDU response format."
         *
         * "If the request was encoded using short APDU encoding,
         * the authenticator MUST respond using ISO 7816-4 APDU chaining."
         *
         * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#nfc-fragmentation
         *
         * In the best case, extended length is supported by device and authenticator, so we don't need to
         * parse chained APDUs coming from the authenticator.
         *
         * We do *not* check for `transport.isExtendedLengthSupported()` here! There are phones (including
         * the Nexus 5X, Nexus 6P) that return "false" to this, but some Security Keys (like Yubikey Neo) still
         * require us to send extended APDUs. So what we do is, send an extended APDU, and if that doesn't
         * work, fall back to a short one.
         */
        if (!transport.isExtendedLengthSupported()) {
            HwTimber.w("Transport protocol does not support extended length. Probably an old device with NFC, such as Nexus 5X, Nexus 6P. We still try sending extended length!");
        }

        ResponseApdu response = transport.transceive(commandApdu.withExtendedApduNe());
        if (response.getSw() != WrongRequestLengthException.SW_WRONG_REQUEST_LENGTH) {
            return response;
        } else {
            HwTimber.d("Received WRONG_REQUEST_LENGTH error. Retrying with short APDU Ne.");
        }

        if (commandFactory.isSuitableForSingleShortApdu(commandApdu)) {
            return transport.transceive(commandApdu.withShortApduNe());
        }

        ResponseApdu lastResponse = null;
        List<CommandApdu> chainedApdus = commandFactory.createChainedApdus(commandApdu);
        for (int i = 0, totalCommands = chainedApdus.size(); i < totalCommands; i++) {
            CommandApdu chainedApdu = chainedApdus.get(i);
            lastResponse = transport.transceive(chainedApdu);

            boolean isLastCommand = (i == totalCommands - 1);
            if (!isLastCommand && !lastResponse.isSuccess()) {
                throw new IOException("Failed to chain apdu " +
                        "(" + i + "/" + (totalCommands - 1) + ", last SW: " + Integer.toHexString(lastResponse.getSw()) + ")");
            }
        }

        if (lastResponse == null) {
            throw new IllegalStateException();
        }

        return lastResponse;
    }

    // ISO/IEC 7816-4
    @NonNull
    private ResponseApdu readChainedResponseIfAvailable(ResponseApdu lastResponse) throws
            IOException {
        if (lastResponse.getSw1() != APDU_SW1_RESPONSE_AVAILABLE) {
            return lastResponse;
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(lastResponse.getData());

        do {
            // GET RESPONSE ISO/IEC 7816-4 par.7.6.1
            CommandApdu getResponse = commandFactory.createGetResponseCommand(lastResponse.getSw2());
            lastResponse = transport.transceive(getResponse);
            result.write(lastResponse.getData());
        } while (lastResponse.getSw1() == APDU_SW1_RESPONSE_AVAILABLE);

        result.write(lastResponse.getSw1());
        result.write(lastResponse.getSw2());

        return ResponseApdu.fromBytes(result.toByteArray());
    }

    // endregion

    @NonNull
    public Fido2CommandApduFactory getCommandFactory() {
        return commandFactory;
    }

    /**
     * GetVersion Request
     * https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
     * <p>
     * The FIDO Client can query the U2F token about the U2F protocol version that it implements.
     *
     * @return should return "U2F_V2"
     */
    private byte[] readVersion() throws IOException {
        CommandApdu getDataUserIdCommand = commandFactory.createVersionCommand();
        ResponseApdu responseApdu = communicateOrThrow(getDataUserIdCommand);
        return responseApdu.getData();
    }

    public boolean isConnected() {
        return transport.isConnected();
    }

    public boolean isSupportResidentKeys() {
        return ctap2Info != null && ctap2Info.options().rk();
    }

    public boolean isSupportClientPin() {
        return ctap2Info != null && ctap2Info.options().clientPin() != null;
    }

    public boolean isClientPinSet() {
        if (ctap2Info == null) {
            return false;
        }
        Boolean clientPin = ctap2Info.options().clientPin();
        return clientPin != null && clientPin;
    }

    public boolean isSupportUserVerification() {
        return ctap2Info != null && ctap2Info.options().uv() != null;
    }

    public boolean isSupportUserPresence() {
        return ctap2Info != null && ctap2Info.options().up();
    }

    public boolean isCtap2Capable() {
        return !isForceCtap1 && ctap2Info != null;
    }

    public void setForceCtap1(boolean isForceCtap1) {
        this.isForceCtap1 = isForceCtap1;
    }

    @Nullable
    public PinToken getCachedPinToken() {
        return cachedPinToken;
    }

    public void setCachedPinToken(PinToken pinToken) {
        this.cachedPinToken = pinToken;
    }
}
