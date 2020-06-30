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

package de.cotech.hw.piv.internal;


import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.AppletFileNotFoundException;
import de.cotech.hw.exceptions.ClaNotSupportedException;
import de.cotech.hw.exceptions.ConditionsNotSatisfiedException;
import de.cotech.hw.exceptions.InsNotSupportedException;
import de.cotech.hw.exceptions.SelectAppletException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.Iso7816TLV;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo.SecurityKeyType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.piv.PivKeyReference;
import de.cotech.hw.piv.exceptions.PivWrongPinException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.util.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;


@RestrictTo(Scope.LIBRARY_GROUP)
public class PivAppletConnection {
    private static final int APDU_SW1_RESPONSE_AVAILABLE = 0x61;
    private static final int RESPONSE_SW1_INCORRECT_LENGTH = 0x6c;

    @NonNull
    private final Transport transport;
    @NonNull
    private final List<byte[]> aidPrefixes;
    private final PivCommandApduFactory commandFactory;

    private SecurityKeyType securityKeyType;

    private byte[] connectedAppletAid;

    private boolean isVerifyOk;


    public static PivAppletConnection getInstanceForTransport(
            @NonNull Transport transport,
            @NonNull List<byte[]> aidPrefixes) {
        return new PivAppletConnection(transport, aidPrefixes, new PivCommandApduFactory());
    }


    private PivAppletConnection(@NonNull Transport transport, @NonNull List<byte[]> aidPrefixes,
            PivCommandApduFactory commandFactory) {
        this.transport = transport;
        this.aidPrefixes = aidPrefixes;
        this.commandFactory = commandFactory;
    }

    // region connection management

    public void connectIfNecessary() throws IOException {
        if (connectedAppletAid != null) {
            refreshConnectionCapabilities();
            return;
        }

        connectToDevice();
    }

    /**
     * Connect to device and select PIV applet
     */
    private void connectToDevice() throws IOException {
        try {
            byte[] selectedAid = selectFilesFromPrefixOrFail();

            determineSecurityKeyType();

            refreshConnectionCapabilities();

            connectedAppletAid = selectedAid;
            resetPwState();
        } catch (IOException e) {
            transport.release();
            throw e;
        }
    }

    public void resetPwState() {
        isVerifyOk = false;
    }

    private byte[] selectFilesFromPrefixOrFail() throws IOException {
        for (byte[] fileAid : aidPrefixes) {
            byte[] initializedAid = selectFileOrReactivateOrFail(fileAid);
            if (initializedAid != null) {
                return initializedAid;
            }
        }
        throw new SelectAppletException(aidPrefixes, "PIV");
    }

    private byte[] selectFileOrReactivateOrFail(byte[] fileAid) throws IOException {
        CommandApdu select = commandFactory.createSelectFileCommand(fileAid);

        try {
            communicateOrThrow(select);
            return fileAid;
        } catch (AppletFileNotFoundException e) {
            return null;
        }
    }

    @VisibleForTesting
    void determineSecurityKeyType() {
        securityKeyType = transport.getSecurityKeyTypeIfAvailable();
        if (securityKeyType != null) {
            return;
        }

        securityKeyType = SecurityKeyType.UNKNOWN;
    }

    private void refreshConnectionCapabilities() {
        // TODO?
    }

    public byte[] getConnectedAppletAid() {
        return connectedAppletAid;
    }

    // endregion

    // region communication

    public ResponseApdu communicateOrThrow(CommandApdu commandApdu) throws IOException {
        ResponseApdu response = communicate(commandApdu);

        if (response.isSuccess()) {
            return response;
        }

        if ((response.getSw() & (short) 0xFFF0) == PivWrongPinException.SW_WRONG_PIN_RETRIES_BASE) {
            int retries = response.getSw() & 0x000F;
            throw new PivWrongPinException(retries);
        }

        switch (response.getSw()) {
            case PivWrongPinException.SW_WRONG_PIN:
                throw new PivWrongPinException(0);
            case AppletFileNotFoundException.SW_FILE_NOT_FOUND:
                throw new AppletFileNotFoundException();
            case ClaNotSupportedException.SW_CLA_NOT_SUPPORTED:
                throw new ClaNotSupportedException();
            case ConditionsNotSatisfiedException.SW_CONDITIONS_NOT_SATISFIED:
                throw new ConditionsNotSatisfiedException();
            case InsNotSupportedException.SW_INS_NOT_SUPPORTED:
                throw new InsNotSupportedException();
            default:
                throw new SecurityKeyException("UNKNOWN", response.getSw());
        }
    }

    /**
     * Transceives APDU
     * Splits extended APDU into short APDUs and chains them if necessary
     * Performs GET RESPONSE command(ISO/IEC 7816-4 par.7.6.1) on retrieving if necessary
     *
     * @param commandApdu short or extended APDU to transceive
     * @return response from the card
     */
    public ResponseApdu communicate(CommandApdu commandApdu) throws IOException {
        ResponseApdu lastResponse;

        lastResponse = transceiveWithChaining(commandApdu);
        if (lastResponse.getSw1() == RESPONSE_SW1_INCORRECT_LENGTH && lastResponse.getSw2() != 0) {
            commandApdu = commandApdu.withNe(lastResponse.getSw2());
            lastResponse = transceiveWithChaining(commandApdu);
        }
        return readChainedResponseIfAvailable(lastResponse);
    }

    @NonNull
    private ResponseApdu transceiveWithChaining(CommandApdu commandApdu) throws IOException {
        // NOTE: Currently always using short APDUs for PIV
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
                throw new IOException("Failed to chain APDU " +
                        "(" + i + "/" + (totalCommands-1) + ", last SW: " + Integer.toHexString(lastResponse.getSw()) + ")");
            }
        }

        if (lastResponse == null) {
            throw new IllegalStateException();
        }

        return lastResponse;
    }

    @NonNull
    private ResponseApdu readChainedResponseIfAvailable(ResponseApdu lastResponse) throws IOException {
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

    // region pin management

    public void verifyPin(ByteSecret pinSecret) throws IOException {
        if (isVerifyOk) {
            return;
        }

        ByteSecret formattedPinSecret = PivPinFormatter.format(pinSecret);

        byte[] pin = formattedPinSecret.unsafeGetByteCopy();
        CommandApdu verifyPw1ForOtherCommand = commandFactory.createVerifyCommand(0x80, pin);
        Arrays.fill(pin, (byte) 0);
        communicateOrThrow(verifyPw1ForOtherCommand);

        isVerifyOk = true;
    }

    // endregion

    private byte[] readData(CommandApdu command) throws IOException {
        ResponseApdu response = communicate(command);
        if (!response.isSuccess()) {
            throw new SecurityKeyException("Failed to get pw status bytes", response.getSw());
        }
        return response.getData();
    }

    public PivCommandApduFactory getCommandFactory() {
        return commandFactory;
    }

    public byte[] retrieveCertificateBytes(PivKeyReference keyReference) throws IOException {
        byte[] getCertData = getData(keyReference.dataObject);
        Iso7816TLV responseTlv = Iso7816TLV.readSingle(getCertData, false);
        Iso7816TLV responseTlv0x70 = Iso7816TLV.find(responseTlv, 0x70);
        if (responseTlv0x70 == null) {
            throw new IOException("Could not find expected certificate tag 0x70!");
        }
        return responseTlv0x70.mV;
    }

    public byte[] getData(String dataObjectHex) throws IOException {
        byte[] dataObject = Hex.decodeHex(dataObjectHex);
        byte[] retrieve = Iso7816TLV.encode(0x5c, dataObject);
        CommandApdu commandApdu = commandFactory.createGetDataCommand(retrieve);
        ResponseApdu responseApdu = communicateOrThrow(commandApdu);

        Iso7816TLV responseTlv = Iso7816TLV.readSingle(responseApdu.getData(), false);
        if (responseTlv.mT != 0x53) {
            throw new IOException("Expected TLV tag 0x53, found " + Integer.toHexString(responseTlv.mT));
        }

        return responseTlv.mV;
    }
}
