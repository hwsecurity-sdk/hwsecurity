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


import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.internal.iso7816.CommandApdu;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.util.ArrayList;
import java.util.List;


@RestrictTo(Scope.LIBRARY_GROUP)
public class OpenPgpCommandApduFactory {
    private static final OpenPgpCommandApduDescriber DESCRIBER = new OpenPgpCommandApduDescriber();

    // The spec allows 255, but for compatibility with non-compliant security keys we use 254 here
    // See https://github.com/open-keychain/open-keychain/issues/2049
    private static final int MAX_APDU_NC_SHORT_OPENPGP_WORKAROUND = CommandApdu.MAX_APDU_NC_SHORT - 1;

    private static final int CLA = 0x00;
    private static final int MASK_CLA_CHAINING = 1 << 4;

    static final int INS_SELECT_FILE = 0xA4;
    private static final int P1_SELECT_FILE = 0x04;

    static final int INS_ACTIVATE_FILE = 0x44;
    static final int INS_TERMINATE_DF = 0xE6;
    static final int INS_GET_RESPONSE = 0xC0;

    static final int INS_INTERNAL_AUTHENTICATE = 0x88;
    private static final int P1_INTERNAL_AUTH_SECURE_MESSAGING = 0x01;

    static final int INS_VERIFY = 0x20;
    private static final int P2_VERIFY_PW1_SIGN = 0x81;
    private static final int P2_VERIFY_PW1_OTHER = 0x82;
    private static final int P2_VERIFY_PW3 = 0x83;

    static final int INS_CHANGE_REFERENCE_DATA = 0x24;
    private static final int P2_CHANGE_REFERENCE_DATA_PW1 = 0x81;
    private static final int P2_CHANGE_REFERENCE_DATA_PW3 = 0x83;

    static final int INS_RESET_RETRY_COUNTER = 0x2C;
    private static final int P1_RESET_RETRY_COUNTER_NEW_PW = 0x02;
    private static final int P2_RESET_RETRY_COUNTER = 0x81;

    static final int INS_PERFORM_SECURITY_OPERATION = 0x2A;
    private static final int P1_PSO_DECIPHER = 0x80;
    private static final int P1_PSO_COMPUTE_DIGITAL_SIGNATURE = 0x9E;
    private static final int P2_PSO_DECIPHER = 0x86;
    private static final int P2_PSO_COMPUTE_DIGITAL_SIGNATURE = 0x9A;

    static final int INS_SELECT_DATA = 0xA5;
    private static final int P1_SELECT_DATA_FOURTH = 0x03;
    private static final int P2_SELECT_DATA = 0x04;
    private static final byte[] CP_SELECT_DATA_CARD_HOLDER_CERT = Hex.decode("60045C027F21");

    static final int INS_GET_DATA = 0xCA;
    static final int DO_GET_DATA_CARD_HOLDER_CERT = 0x7F21;
    static final int DO_GET_DATA_URL = 0x5F50;
    static final int DO_GET_DATA_CARDHOLDER_RELATED_DATA = 0x0065;
    static final int DO_GET_DATA_APPLICATION_RELATED_DATA = 0x006E;

    static final int INS_PUT_DATA = 0xDA;

    static final int INS_PUT_DATA_ODD = 0xDB;
    private static final int P1_PUT_DATA_ODD_KEY = 0x3F;
    private static final int P2_PUT_DATA_ODD_KEY = 0xFF;

    static final int INS_GENERATE_RETRIEVE_ASYMMETRIC_KEY = 0x47;
    private static final int P1_GAKP_GENERATE = 0x80;
    private static final int P1_GAKP_READ_PUBKEY_TEMPLATE = 0x81;
    private static final byte[] CRT_GAKP_SECURE_MESSAGING = Hex.decode("A600");

    private static final int P1_EMPTY = 0x00;
    private static final int P2_EMPTY = 0x00;

    @NonNull
    public CommandApdu createVerifyPw1ForOtherCommand(byte[] pin) {
        return CommandApdu.create(CLA, INS_VERIFY, P1_EMPTY, P2_VERIFY_PW1_OTHER, pin).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataCommand(int p1, int p2) {
        return CommandApdu.create(CLA, INS_GET_DATA, p1, p2, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataCommand(int dataObject) {
        int p1 = (dataObject & 0xFF00) >> 8;
        int p2 = dataObject & 0xFF;
        return CommandApdu.create(CLA, INS_GET_DATA, p1, p2, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createPutDataCommand(int dataObject, byte[] data) {
        int p1 = (dataObject & 0xFF00) >> 8;
        int p2 = dataObject & 0xFF;
        return CommandApdu.create(CLA, INS_PUT_DATA, p1, p2, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createPutKeyCommand(byte[] keyBytes) {
        // the odd PUT DATA INS is for compliance with ISO 7816-8. This is used only to put key data on the card
        return CommandApdu.create(CLA, INS_PUT_DATA_ODD, P1_PUT_DATA_ODD_KEY, P2_PUT_DATA_ODD_KEY, keyBytes).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createComputeDigitalSignatureCommand(byte[] data) {
        return CommandApdu.create(CLA, INS_PERFORM_SECURITY_OPERATION, P1_PSO_COMPUTE_DIGITAL_SIGNATURE,
                P2_PSO_COMPUTE_DIGITAL_SIGNATURE, data, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createDecipherCommand(byte[] data, int expectedLength) {
        return CommandApdu.create(CLA, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECIPHER, P2_PSO_DECIPHER, data,
                expectedLength).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createChangePw3Command(byte[] adminPin, byte[] newAdminPin) {
        return CommandApdu.create(CLA, INS_CHANGE_REFERENCE_DATA, P1_EMPTY,
                P2_CHANGE_REFERENCE_DATA_PW3, Arrays.concatenate(adminPin, newAdminPin)).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createResetPw1Command(byte[] newPin) {
        return CommandApdu.create(CLA, INS_RESET_RETRY_COUNTER, P1_RESET_RETRY_COUNTER_NEW_PW,
                P2_RESET_RETRY_COUNTER, newPin).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createVerifyPw1ForSignatureCommand(byte[] pin) {
        return CommandApdu.create(CLA, INS_VERIFY, P1_EMPTY, P2_VERIFY_PW1_SIGN, pin).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createVerifyPw3Command(byte[] pin) {
        return CommandApdu.create(CLA, INS_VERIFY, P1_EMPTY, P2_VERIFY_PW3, pin).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createTerminateDfCommand() {
        return CommandApdu.create(CLA, INS_TERMINATE_DF, P1_EMPTY, P2_EMPTY).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createReactivateCommand() {
        return CommandApdu.create(CLA, INS_ACTIVATE_FILE, P1_EMPTY, P2_EMPTY).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createInternalAuthForSecureMessagingCommand(byte[] authData) {
        return CommandApdu.create(CLA, INS_INTERNAL_AUTHENTICATE, P1_INTERNAL_AUTH_SECURE_MESSAGING, P2_EMPTY, authData,
                CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createInternalAuthCommand(byte[] authData) {
        return CommandApdu.create(CLA, INS_INTERNAL_AUTHENTICATE, P1_EMPTY, P2_EMPTY, authData, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGenerateKeyCommand(int slot) {
        return CommandApdu.create(CLA, INS_GENERATE_RETRIEVE_ASYMMETRIC_KEY,
                P1_GAKP_GENERATE, P2_EMPTY, new byte[]{(byte) slot, 0x00}, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createRetrievePublicKey(int slot) {
        return CommandApdu.create(CLA, INS_GENERATE_RETRIEVE_ASYMMETRIC_KEY,
                P1_GAKP_READ_PUBKEY_TEMPLATE, P2_EMPTY, new byte[]{(byte) slot, 0x00}, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createRetrieveSecureMessagingPublicKeyCommand() {
        // see https://github.com/ANSSI-FR/SmartPGP/blob/master/secure_messaging/smartpgp_sm.pdf
        return CommandApdu.create(CLA, INS_GENERATE_RETRIEVE_ASYMMETRIC_KEY, P1_GAKP_READ_PUBKEY_TEMPLATE, P2_EMPTY,
                CRT_GAKP_SECURE_MESSAGING, CommandApdu.MAX_APDU_NE_EXTENDED).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createSelectSecureMessagingCertificateCommand() {
        // see https://github.com/ANSSI-FR/SmartPGP/blob/master/secure_messaging/smartpgp_sm.pdf
        // this command selects the fourth occurence of data tag 7F21
        return CommandApdu.create(CLA, INS_SELECT_DATA, P1_SELECT_DATA_FOURTH, P2_SELECT_DATA,
                CP_SELECT_DATA_CARD_HOLDER_CERT).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataCardHolderCertCommand() {
        return createGetDataCommand(DO_GET_DATA_CARD_HOLDER_CERT).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataUrlCommand() {
        return createGetDataCommand(DO_GET_DATA_URL).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataUserIdCommand() {
        return createGetDataCommand(DO_GET_DATA_CARDHOLDER_RELATED_DATA).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGetDataApplicationRelatedData() {
        return createGetDataCommand(DO_GET_DATA_APPLICATION_RELATED_DATA).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4
    // SELECT command always as short APDU
    @NonNull
    public CommandApdu createSelectFileCommand(byte[] fileAid) {
        return CommandApdu.create(CLA, INS_SELECT_FILE, P1_SELECT_FILE, P2_EMPTY, fileAid, CommandApdu.MAX_APDU_NE_SHORT).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4 par.7.6.1
    @NonNull
    public CommandApdu createGetResponseCommand(int lastResponseSw2) {
        return CommandApdu.create(CLA, INS_GET_RESPONSE, P1_EMPTY, P2_EMPTY, lastResponseSw2).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4
    @NonNull
    public CommandApdu createShortApdu(CommandApdu apdu) {
        int ne = Math.min(apdu.getNe(), CommandApdu.MAX_APDU_NE_SHORT);
        return apdu.withNe(ne);
    }

    // ISO/IEC 7816-4
    @NonNull
    public List<CommandApdu> createChainedApdus(CommandApdu apdu) {
        ArrayList<CommandApdu> result = new ArrayList<>();

        int offset = 0;
        byte[] data = apdu.getData();
        while (offset < data.length) {
            int curLen = Math.min(MAX_APDU_NC_SHORT_OPENPGP_WORKAROUND, data.length - offset);
            boolean last = offset + curLen >= data.length;
            int cla = apdu.getCLA() + (last ? 0 : MASK_CLA_CHAINING);

            CommandApdu cmd;
            if (last) {
                int ne = Math.min(apdu.getNe(), CommandApdu.MAX_APDU_NE_SHORT);
                cmd = CommandApdu.create(cla, apdu.getINS(), apdu.getP1(), apdu.getP2(), data, offset, curLen, ne, DESCRIBER);
            } else {
                cmd = CommandApdu.create(cla, apdu.getINS(), apdu.getP1(), apdu.getP2(), data, offset, curLen, 0, DESCRIBER);
            }
            result.add(cmd);

            offset += curLen;
        }

        return result;
    }

    public boolean isSuitableForShortApdu(CommandApdu apdu) {
        return apdu.getNc() <= MAX_APDU_NC_SHORT_OPENPGP_WORKAROUND;
    }
}
