/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.fido.internal;


import java.util.ArrayList;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.iso7816.CommandApdu;


/**
 * Follows "FIDO U2F Raw Message Formats" v1.2
 * https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class FidoU2fCommandApduFactory {
    private static final FidoCommandApduDescriber DESCRIBER = new FidoCommandApduDescriber();

    // ISO/IEC 7816-4
    private static final int MAX_APDU_NC = 255;
    private static final int MAX_APDU_NC_EXT = 65535;
    private static final int MAX_APDU_NE = 256;
    private static final int MAX_APDU_NE_EXT = 65536;

    private static final int MASK_CLA_CHAINING = 1 << 4;

    private static final int CLA = 0x00;
    private static final int INS_SELECT_FILE = 0xA4;
    private static final int P1_SELECT_FILE = 0x04;
    private static final int INS_GET_RESPONSE = 0xC0;

    private static final int P1_EMPTY = 0x00;
    private static final int P2_EMPTY = 0x00;

    // "FIDO U2F Raw Message Formats", Section 3.1.1 Command and parameter values
    // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
    private static final int U2F_REGISTER = 0x01;
    private static final int U2F_AUTHENTICATE = 0x02;
    private static final int U2F_VERSION = 0x03;

    private static final int U2F_AUTHENTICATE_P1_ENFORCE_USER_PRESENCE_AND_SIGN = 0x03;
    private static final int U2F_AUTHENTICATE_P1_CHECK_ONLY = 0x07;
    private static final int U2F_AUTHENTICATE_P1_DONT_ENFORCE_USER_PRESENCE_AND_SIGN = 0x08;


    @NonNull
    public CommandApdu createRegistrationCommand(byte[] data) {
        return CommandApdu.create(CLA, U2F_REGISTER, U2F_AUTHENTICATE_P1_ENFORCE_USER_PRESENCE_AND_SIGN, P2_EMPTY, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createAuthenticationCommand(byte[] data) {
        return CommandApdu.create(CLA, U2F_AUTHENTICATE, U2F_AUTHENTICATE_P1_ENFORCE_USER_PRESENCE_AND_SIGN, P2_EMPTY, data).withDescriber(DESCRIBER);
    }

    @NonNull
    public CommandApdu createVersionCommand() {
        return CommandApdu.create(CLA, U2F_VERSION, P1_EMPTY, P2_EMPTY).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4
    @NonNull
    public CommandApdu createSelectFileCommand(byte[] fileAid) {
        return CommandApdu.create(CLA, INS_SELECT_FILE, P1_SELECT_FILE, P2_EMPTY, fileAid).withDescriber(DESCRIBER);
    }

    // GET RESPONSE ISO/IEC 7816-4 par.7.6.1
    @NonNull
    public CommandApdu createGetResponseCommand(int lastResponseSw2) {
        return CommandApdu.create(CLA, INS_GET_RESPONSE, P1_EMPTY, P2_EMPTY, lastResponseSw2).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4
    @NonNull
    public CommandApdu createShortApdu(CommandApdu apdu) {
        int ne = Math.min(apdu.getNe(), MAX_APDU_NE);
        return CommandApdu.create(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), apdu.getData(), ne).withDescriber(DESCRIBER);
    }

    // ISO/IEC 7816-4
    @NonNull
    public List<CommandApdu> createChainedApdus(CommandApdu apdu) {
        ArrayList<CommandApdu> result = new ArrayList<>();

        int offset = 0;
        byte[] data = apdu.getData();
        while (offset < data.length) {
            int curLen = Math.min(MAX_APDU_NC, data.length - offset);
            boolean last = offset + curLen >= data.length;
            int cla = apdu.getCLA() + (last ? 0 : MASK_CLA_CHAINING);

            CommandApdu cmd;
            if (last) {
                int ne = Math.min(apdu.getNe(), MAX_APDU_NE);
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
        return apdu.getData().length <= MAX_APDU_NC;
    }

    public boolean isSuitableForExtendedApdu(CommandApdu commandApdu) {
        return commandApdu.getCLA() == CLA && commandApdu.getINS() != INS_SELECT_FILE;
    }
}