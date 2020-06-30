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
import de.cotech.hw.internal.iso7816.CommandApdu;

import java.util.ArrayList;
import java.util.List;


@RestrictTo(Scope.LIBRARY_GROUP)
public class PivCommandApduFactory {
    private static final PivCommandApduDescriber DESCRIBER = new PivCommandApduDescriber();

    private static final int CLA = 0x00;
    private static final int MASK_CLA_CHAINING = 1 << 4;

    private static final int INS_SELECT_FILE = 0xA4;
    private static final int P1_SELECT_FILE = 0x04;

    private static final int INS_GENERAL_AUTHENTICATE = 0x87;

    private static final int INS_RESET_RETRY_COUNTER = 0x2C;
    private static final int P2_RESET_RETRY_COUNTER_CARD_APPLICATION_PIN = 0x80;

    private static final int INS_GET_RESPONSE = 0xC0;

    private static final int INS_VERIFY = 0x20;
    private static final int P2_VERIFY_PW1_SIGN = 0x81;
    private static final int P2_VERIFY_PW1_OTHER = 0x82;
    private static final int P2_VERIFY_PW3 = 0x83;

    private static final int INS_GET_DATA = 0xCB;
    private static final int P1_GET_DATA = 0x3F;
    private static final int P2_GET_DATA = 0xFF;

    private static final int P1_EMPTY = 0x00;
    private static final int P2_EMPTY = 0x00;
    private static final int P1_AUTHENTICATE_RSA = 0x07;
    private static final int P1_AUTHENTICATE_P256 = 0x11;
    private static final int P1_AUTHENTICATE_P384 = 0x14;
    private static final int P2_AUTHENTICATE = 0x9A;

    @NonNull
    public CommandApdu createGetDataCommand(byte[] dataObject) {
        return CommandApdu.create(CLA, INS_GET_DATA, P1_GET_DATA, P2_GET_DATA, dataObject, 0).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createVerifyCommand(int slot, byte[] data) {
        return CommandApdu.create(CLA, INS_VERIFY, P1_EMPTY, slot, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGeneralAuthenticateP256(int slot, byte[] data) {
        return CommandApdu.create(CLA, INS_GENERAL_AUTHENTICATE, P1_AUTHENTICATE_P256, slot, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGeneralAuthenticateP384(int slot, byte[] data) {
        return CommandApdu.create(CLA, INS_GENERAL_AUTHENTICATE, P1_AUTHENTICATE_P384, slot, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createGeneralAuthenticateRSA(int slot, byte[] data) {
        return CommandApdu.create(CLA, INS_GENERAL_AUTHENTICATE, P1_AUTHENTICATE_RSA, slot, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createResetRetryCounter(byte[] data) {
        return CommandApdu.create(CLA, INS_RESET_RETRY_COUNTER, P1_EMPTY, P2_RESET_RETRY_COUNTER_CARD_APPLICATION_PIN, data).withDescriber(DESCRIBER);
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
    public List<CommandApdu> createChainedApdus(CommandApdu apdu) {
        ArrayList<CommandApdu> result = new ArrayList<>();

        int offset = 0;
        byte[] data = apdu.getData();
        while (offset < data.length) {
            int curLen = Math.min(CommandApdu.MAX_APDU_NC_SHORT, data.length - offset);
            boolean last = offset + curLen >= data.length;
            int cla = apdu.getCLA() + (last ? 0 : MASK_CLA_CHAINING);

            CommandApdu cmd;
            if (last) {
                // TODO: check this!
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

    public boolean isSuitableForSingleShortApdu(CommandApdu apdu) {
        return apdu.getNc() <= CommandApdu.MAX_APDU_NC_SHORT;
    }
}
