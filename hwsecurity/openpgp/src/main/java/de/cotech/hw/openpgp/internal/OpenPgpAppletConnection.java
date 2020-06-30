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

package de.cotech.hw.openpgp.internal;


import android.os.SystemClock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import de.cotech.hw.BuildConfig;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.AppletFileNotFoundException;
import de.cotech.hw.exceptions.ClaNotSupportedException;
import de.cotech.hw.exceptions.ConditionsNotSatisfiedException;
import de.cotech.hw.exceptions.FileInTerminationStateException;
import de.cotech.hw.exceptions.InsNotSupportedException;
import de.cotech.hw.exceptions.SelectAppletException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.SecurityKeyInfo.SecurityKeyType;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.openpgp.CardCapabilities;
import de.cotech.hw.openpgp.OpenPgpCapabilities;
import de.cotech.hw.openpgp.exceptions.OpenPgpLockedException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPinTooShortException;
import de.cotech.hw.openpgp.exceptions.OpenPgpWrongPinException;
import de.cotech.hw.openpgp.exceptions.SecurityKeyTerminatedException;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.securemessaging.SCP11bSecureMessaging;
import de.cotech.hw.openpgp.internal.securemessaging.SecureMessaging;
import de.cotech.hw.openpgp.internal.securemessaging.SecureMessagingException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.util.HwTimber;


/**
 * This class provides a communication interface to OpenPGP applications on ISO SmartCard compliant
 * devices.
 * For the full specs, see http://g10code.com/docs/openpgp-card-2.0.pdf
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class OpenPgpAppletConnection {
    private static final int APDU_SW1_RESPONSE_AVAILABLE = 0x61;
    private static final int RESPONSE_SW1_INCORRECT_LENGTH = 0x6c;

    @NonNull
    private final Transport transport;
    @NonNull
    private final List<byte[]> aidPrefixes;
    @Nullable
    private final KeyStore smKeyStore;
    private final OpenPgpCommandApduFactory commandFactory;

    private SecurityKeyType securityKeyType;
    private CardCapabilities cardCapabilities;
    private OpenPgpCapabilities openPgpCapabilities;

    private SecureMessaging secureMessaging;

    private boolean isOpenPgpAppletConnected;

    private boolean isPw1ValidatedForSignature; // Mode 81
    private boolean isPw1ValidatedForOther; // Mode 82
    private boolean isPw3Validated;


    public static OpenPgpAppletConnection getInstanceForTransport(
            @NonNull Transport transport,
            @NonNull List<byte[]> aidPrefixes) {
        return new OpenPgpAppletConnection(transport, aidPrefixes, null, new OpenPgpCommandApduFactory());
    }


    private OpenPgpAppletConnection(@NonNull Transport transport, @NonNull List<byte[]> aidPrefixes,
                                    @Nullable KeyStore smKeyStore, OpenPgpCommandApduFactory commandFactory) {
        this.transport = transport;
        this.aidPrefixes = aidPrefixes;
        this.smKeyStore = smKeyStore;
        this.commandFactory = commandFactory;
    }

    // region connection management

    public void connectIfNecessary() throws IOException {
        if (isOpenPgpAppletConnected) {
            refreshConnectionCapabilities();
            return;
        }

        connectToDevice();
    }

    /**
     * Connect to device and select pgp applet
     */
    private void connectToDevice() throws IOException {
        try {
            // dummy instance for initial communicate() calls
            cardCapabilities = new CardCapabilities();

            determineSecurityKeyType();

            byte[] selectedAid = selectFilesFromPrefixOrFail();

            try {
                refreshConnectionCapabilities();
            } catch (ConditionsNotSatisfiedException e) {
                HwTimber.d("Got conditions of use not satisfied while establishing connection");
                attemptReactivate(selectedAid);

                HwTimber.d("Retrying failed connection");
                selectFilesFromPrefixOrFail();
                refreshConnectionCapabilities();
            }

            logAidInformation();

            isOpenPgpAppletConnected = true;
            resetPwState();

            smEstablishIfAvailable(smKeyStore);
        } catch (IOException e) {
            transport.release();
            throw e;
        }
    }

    public void resetPwState() {
        isPw1ValidatedForOther = false;
        isPw1ValidatedForSignature = false;
        isPw3Validated = false;
    }

    private byte[] selectFilesFromPrefixOrFail() throws IOException {
        for (byte[] fileAid : aidPrefixes) {
            byte[] initializedAid = selectFileOrReactivateOrFail(fileAid);
            if (initializedAid != null) {
                return initializedAid;
            }
        }
        throw new SelectAppletException(aidPrefixes, "OpenPGP");
    }

    private byte[] selectFileOrReactivateOrFail(byte[] fileAid) throws IOException {
        CommandApdu select = commandFactory.createSelectFileCommand(fileAid);

        try {
            communicateOrThrow(select);
            return fileAid;
        } catch (AppletFileNotFoundException e) {
            return null;
        } catch (FileInTerminationStateException e) {
            if (attemptReactivate(fileAid)) {
                return fileAid;
            }
        }

        return null;
    }

    private boolean attemptReactivate(byte[] fileAid) throws IOException {
        HwTimber.d("Attempting to reactivate from unsuccessful reset");
        CommandApdu reactivate = commandFactory.createReactivateCommand();
        ResponseApdu response = communicate(reactivate);

        if (!response.isSuccess()) {
            throw new SecurityKeyTerminatedException("Applet terminated, and inline reactivation failed!");
        }

        HwTimber.d("Reactivation successful");
        CommandApdu select = commandFactory.createSelectFileCommand(fileAid);
        response = communicate(select);
        return response.isSuccess();
    }

    @VisibleForTesting
    void determineSecurityKeyType() throws IOException {
        securityKeyType = transport.getSecurityKeyTypeIfAvailable();
        if (securityKeyType != null) {
            return;
        }

//        CommandApdu selectFidesmoApdu = commandFactory.createSelectFileCommand(AID_PREFIX_FIDESMO);
//        if (communicate(selectFidesmoApdu).isSuccess()) {
//            securityKeyType = SecurityKeyType.FIDESMO;
//            return;
//        }

        /* We could determine if this is a yubikey here. The info isn't used at the moment, so we save the roundtrip
        // AID from https://github.com/Yubico/ykneo-oath/blob/master/build.xml#L16
        CommandApdu selectYubicoApdu = commandFactory.createSelectFileCommand("A000000527200101");
        if (communicate(selectYubicoApdu).isSuccess()) {
            securityKeyType = SecurityKeyType.YUBIKEY_UNKNOWN;
            return;
        }
        */

        securityKeyType = SecurityKeyType.UNKNOWN;
    }

    public void refreshConnectionCapabilities() throws IOException {
        CommandApdu getDataApplicationRelatedData = commandFactory.createGetDataApplicationRelatedData();
        byte[] rawOpenPgpCapabilities = readData(getDataApplicationRelatedData);

        OpenPgpCapabilities openPgpCapabilities = OpenPgpCapabilities.fromBytes(rawOpenPgpCapabilities);
        setConnectionCapabilities(openPgpCapabilities);
    }

    private void logAidInformation() {
        if (BuildConfig.DEBUG) {
            HwTimber.d("capabilities: %s", openPgpCapabilities);
            HwTimber.d(openPgpCapabilities.hasEncryptKey() ? "encryption key present" : "no encryption key present");
        }
    }

    private void setConnectionCapabilities(OpenPgpCapabilities openPgpCapabilities) throws IOException {
        this.openPgpCapabilities = openPgpCapabilities;
        this.cardCapabilities = new CardCapabilities(openPgpCapabilities.getHistoricalBytes());
    }

    // endregion

    // region communication

    /**
     * Transceives APDU
     * Splits extended APDU into short APDUs and chains them if necessary
     * Performs GET RESPONSE command(ISO/IEC 7816-4 par.7.6.1) on retrieving if necessary
     *
     * @param commandApdu short or extended APDU to transceive
     * @return response from the card
     */
    public ResponseApdu communicate(CommandApdu commandApdu) throws IOException {
        commandApdu = smEncryptIfAvailable(commandApdu);

        ResponseApdu lastResponse;

        lastResponse = transceiveWithChaining(commandApdu);
        if (lastResponse.getSw1() == RESPONSE_SW1_INCORRECT_LENGTH && lastResponse.getSw2() != 0) {
            commandApdu = commandApdu.withNe(lastResponse.getSw2());
            lastResponse = transceiveWithChaining(commandApdu);
        }
        lastResponse = readChainedResponseIfAvailable(lastResponse);

        lastResponse = smDecryptIfAvailable(lastResponse);

        return lastResponse;
    }

    public ResponseApdu communicateOrThrow(CommandApdu commandApdu) throws IOException {
        ResponseApdu response = communicate(commandApdu);

        if (response.isSuccess()) {
            return response;
        }

        switch (response.getSw()) {
            case OpenPgpWrongPinException.SW_WRONG_PIN:
            case OpenPgpWrongPinException.SW_WRONG_PIN_YKNEO_1:
            case OpenPgpWrongPinException.SW_WRONG_PIN_YKNEO_2:
                // get current number of retries (capabilities must be refreshed for USB!)
                refreshConnectionCapabilities();
                int pinRetriesLeft = getOpenPgpCapabilities().getPw1TriesLeft();
                int pukRetriesLeft = getOpenPgpCapabilities().getPw3TriesLeft();
                throw new OpenPgpWrongPinException(pinRetriesLeft, pukRetriesLeft);
            case OpenPgpLockedException.SW_OPENPGP_LOCKED:
            case OpenPgpLockedException.SW_OPENPGP_LOCKED_YKNEO:
                throw new OpenPgpLockedException();
            case OpenPgpPinTooShortException.SW_WRONG_DATA:
            case OpenPgpPinTooShortException.SW_WRONG_REQUEST_LENGTH:
                throw new OpenPgpPinTooShortException();
            case AppletFileNotFoundException.SW_FILE_NOT_FOUND:
                throw new AppletFileNotFoundException();
            case ClaNotSupportedException.SW_CLA_NOT_SUPPORTED:
                throw new ClaNotSupportedException();
            case ConditionsNotSatisfiedException.SW_CONDITIONS_NOT_SATISFIED:
                throw new ConditionsNotSatisfiedException();
            case FileInTerminationStateException.SW_SELECTED_FILE_IN_TERMINATION_STATE:
                throw new FileInTerminationStateException();
            case InsNotSupportedException.SW_INS_NOT_SUPPORTED:
                throw new InsNotSupportedException();
            default:
                throw new SecurityKeyException("UNKNOWN", response.getSw());
        }
    }

    @NonNull
    private ResponseApdu transceiveWithChaining(CommandApdu commandApdu) throws IOException {
        if (cardCapabilities.hasExtended()) {
            return transport.transceive(commandApdu);
        } else if (commandFactory.isSuitableForShortApdu(commandApdu)) {
            CommandApdu shortApdu = commandFactory.createShortApdu(commandApdu);
            return transport.transceive(shortApdu);
        } else if (cardCapabilities.hasChaining()) {
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
        } else {
            throw new IOException("Command too long, and chaining unavailable");
        }
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

    // region secure messaging

    private void smEstablishIfAvailable(KeyStore smKeyStore) throws IOException {
        if (!openPgpCapabilities.isHasScp11bSm()) {
            return;
        }

        try {
            long elapsedRealtimeStart = SystemClock.elapsedRealtime();

            secureMessaging = SCP11bSecureMessaging.establish(this, commandFactory, smKeyStore);
            long elapsedTime = SystemClock.elapsedRealtime() - elapsedRealtimeStart;
            HwTimber.d("Established secure messaging in %d ms", elapsedTime);
        } catch (SecureMessagingException e) {
            secureMessaging = null;
            HwTimber.w("Secure messaging has not been established: %s", e.getMessage());
        }
    }

    private CommandApdu smEncryptIfAvailable(CommandApdu apdu) throws IOException {
        if (secureMessaging == null || !secureMessaging.isEstablished()) {
            return apdu;
        }
        try {
            return secureMessaging.encryptAndSign(apdu);
        } catch (SecureMessagingException e) {
            clearSecureMessaging();
            throw new IOException("secure messaging encrypt/sign failure : " + e.getMessage());
        }
    }

    private ResponseApdu smDecryptIfAvailable(ResponseApdu response) throws IOException {
        if (secureMessaging == null || !secureMessaging.isEstablished()) {
            return response;
        }
        try {
            return secureMessaging.verifyAndDecrypt(response);
        } catch (SecureMessagingException e) {
            clearSecureMessaging();
            throw new IOException("secure messaging verify/decrypt failure : " + e.getMessage());
        }
    }

    public void clearSecureMessaging() {
        if (secureMessaging != null) {
            secureMessaging.clearSession();
        }
        secureMessaging = null;
    }

    // endregion

    // region pin management

    public void verifyPinForSignature(ByteSecret pinSecret) throws IOException {
        if (isPw1ValidatedForSignature) {
            return;
        }

        byte[] pin = pinSecret.unsafeGetByteCopy();
        CommandApdu verifyPw1ForSignatureCommand = commandFactory.createVerifyPw1ForSignatureCommand(pin);
        Arrays.fill(pin, (byte) 0);
        ResponseApdu response = communicateOrThrow(verifyPw1ForSignatureCommand);

        isPw1ValidatedForSignature = true;
    }

    public void verifyPinForOther(ByteSecret pinSecret) throws IOException {
        if (isPw1ValidatedForOther) {
            return;
        }

        byte[] pin = pinSecret.unsafeGetByteCopy();
        CommandApdu verifyPw1ForOtherCommand = commandFactory.createVerifyPw1ForOtherCommand(pin);
        Arrays.fill(pin, (byte) 0);

        communicateOrThrow(verifyPw1ForOtherCommand);

        isPw1ValidatedForOther = true;
    }

    public void verifyPuk(ByteSecret pukSecret) throws IOException {
        if (isPw3Validated) {
            return;
        }

        byte[] puk = pukSecret.unsafeGetByteCopy();
        CommandApdu verifyPw3Command = commandFactory.createVerifyPw3Command(puk);
        communicateOrThrow(verifyPw3Command);

        isPw3Validated = true;
    }

    public void invalidateSingleUsePw1() {
        if (!openPgpCapabilities.isPw1ValidForMultipleSignatures()) {
            isPw1ValidatedForSignature = false;
        }
    }

    public void invalidatePw3() {
        isPw3Validated = false;
    }

    // endregion

    private byte[] readData(CommandApdu command) throws IOException {
        ResponseApdu response = communicateOrThrow(command);
        return response.getData();
    }

    private String readUrl() throws IOException {
        CommandApdu getDataUrlCommand = commandFactory.createGetDataUrlCommand();
        byte[] data = readData(getDataUrlCommand);
        return new String(data).trim();
    }

    private byte[] readUserId() throws IOException {
        CommandApdu getDataUserIdCommand = commandFactory.createGetDataUserIdCommand();
        return readData(getDataUserIdCommand);
    }

    public SecurityKeyInfo readSecurityKeyInfo() throws IOException {
        byte[][] fingerprints = new byte[3][];
        fingerprints[0] = openPgpCapabilities.getFingerprintSign();
        fingerprints[1] = openPgpCapabilities.getFingerprintEncrypt();
        fingerprints[2] = openPgpCapabilities.getFingerprintAuth();

        byte[] aid = openPgpCapabilities.getAid();
        String userId = parseHolderName(readUserId());
        String url = readUrl();
        int pw1TriesLeft = openPgpCapabilities.getPw1TriesLeft();
        int pw3TriesLeft = openPgpCapabilities.getPw3TriesLeft();
        boolean hasLifeCycleManagement = cardCapabilities.hasLifeCycleManagement();

        TransportType transportType = transport.getTransportType();

        return SecurityKeyInfo.create(transportType, securityKeyType, fingerprints, aid, userId, url, pw1TriesLeft,
                pw3TriesLeft, hasLifeCycleManagement);
    }

    public SecurityKeyType getSecurityKeyType() {
        return securityKeyType;
    }

    public OpenPgpCapabilities getOpenPgpCapabilities() {
        return openPgpCapabilities;
    }

    public OpenPgpCommandApduFactory getCommandFactory() {
        return commandFactory;
    }

    private static String parseHolderName(byte[] name) {
        try {
            return (new String(name, 4, name[3])).replace('<', ' ');
        } catch (IndexOutOfBoundsException e) {
            // try-catch for https://github.com/FluffyKaon/OpenPGP-Card
            // Note: This should not happen, but happens with
            // https://github.com/FluffyKaon/OpenPGP-Card, thus return an empty string for now!

            HwTimber.e(e, "Couldn't get holder name, returning empty string!");
            return "";
        }
    }

    public byte[] retrievePublicKey(int slot) throws IOException {
        CommandApdu commandApdu = commandFactory.createRetrievePublicKey(slot);
        ResponseApdu responseApdu = communicateOrThrow(commandApdu);

        return responseApdu.getData();
    }

    public byte[] getData(int dataObject) throws IOException {
        CommandApdu commandApdu = commandFactory.createGetDataCommand(dataObject);
        ResponseApdu responseApdu = communicateOrThrow(commandApdu);
        return responseApdu.getData();
    }

    public void putData(int dataObject, byte[] data) throws IOException {
        CommandApdu commandApdu = commandFactory.createPutDataCommand(dataObject, data);
        communicateOrThrow(commandApdu);
    }

    public void setKeyMetadata(KeyType keyType, Date timestamp, byte[] fingerprint) throws IOException {
        long keyGenerationTimestamp = timestamp.getTime() / 1000;
        byte[] timestampBytes = ByteBuffer.allocate(4).putInt((int) keyGenerationTimestamp).array();

        putData(keyType.getFingerprintObjectId(), fingerprint);
        putData(keyType.getTimestampObjectId(), timestampBytes);
    }
}
