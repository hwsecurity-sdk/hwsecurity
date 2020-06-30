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


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.CommandApduDescriber;
import org.bouncycastle.util.encoders.Hex;


@RestrictTo(Scope.LIBRARY_GROUP)
public class OpenPgpCommandApduDescriber implements CommandApduDescriber {
    @Override
    public String describe(CommandApdu commandApdu) {
        StringBuilder builder = new StringBuilder();
        switch (commandApdu.getINS()) {
            case OpenPgpCommandApduFactory.INS_SELECT_FILE:
                builder.append("SELECT FILE");
                break;
            case OpenPgpCommandApduFactory.INS_ACTIVATE_FILE:
                builder.append("ACTIVATE FILE");
                break;
            case OpenPgpCommandApduFactory.INS_TERMINATE_DF:
                builder.append("TERMINATE DF");
                break;
            case OpenPgpCommandApduFactory.INS_GET_RESPONSE:
                builder.append("GET RESPONSE");
                break;
            case OpenPgpCommandApduFactory.INS_INTERNAL_AUTHENTICATE:
                builder.append("INTERNAL AUTHENTICATE");
                break;
            case OpenPgpCommandApduFactory.INS_VERIFY:
                builder.append("VERIFY");
                break;
            case OpenPgpCommandApduFactory.INS_CHANGE_REFERENCE_DATA:
                builder.append("CHANGE REFERENCE DATA");
                break;
            case OpenPgpCommandApduFactory.INS_RESET_RETRY_COUNTER:
                builder.append("RESET RETRY COUNTER");
                break;
            case OpenPgpCommandApduFactory.INS_PERFORM_SECURITY_OPERATION:
                builder.append("PERFORM SECURITY OPERATION");
                break;
            case OpenPgpCommandApduFactory.INS_SELECT_DATA:
                builder.append("SELECT DATA");
                break;
            case OpenPgpCommandApduFactory.INS_GET_DATA:
                builder.append("GET DATA");
                break;
            case OpenPgpCommandApduFactory.INS_PUT_DATA:
                builder.append("PUT DATA");
                break;
            case OpenPgpCommandApduFactory.INS_PUT_DATA_ODD:
                builder.append("PUT DATA ODD");
                break;
            case OpenPgpCommandApduFactory.INS_GENERATE_RETRIEVE_ASYMMETRIC_KEY:
                builder.append("GENERATE/RETRIEVE ASYMMETRIC KEY");
                break;
        }

        if ((commandApdu.getCLA() & 0x0C) != 0) {
            builder.append(" + SM");
        }
        if ((commandApdu.getCLA() & 0x10) != 0) {
            builder.append(" + CHAIN");
        }

        describeP1P2(commandApdu, builder);

        builder.append(" ");
        builder.append(Hex.toHexString(commandApdu.getData()));

        return builder.toString();
    }

    private void describeP1P2(CommandApdu commandApdu, StringBuilder builder) {
        switch (commandApdu.getINS()) {
            case OpenPgpCommandApduFactory.INS_PUT_DATA:
            case OpenPgpCommandApduFactory.INS_GET_DATA:
                describeDataObjectP1P2(commandApdu, builder);
                return;
            case OpenPgpCommandApduFactory.INS_VERIFY:
                describeVerifyP1P2(commandApdu, builder);
                return;
            case OpenPgpCommandApduFactory.INS_PERFORM_SECURITY_OPERATION:
                describePsoP1P2(commandApdu, builder);
                return;
        }

        int p1 = commandApdu.getP1();
        int p2 = commandApdu.getP2();
        if (p1 != 0x00 || p2 != 0x00) {
            builder
                    .append(" [")
                    .append(Integer.toHexString(p1))
                    .append(" ")
                    .append(Integer.toHexString(p2))
                    .append("]");
        }
    }

    private void describePsoP1P2(CommandApdu commandApdu, StringBuilder builder) {
        int p1p2 = (commandApdu.getP1() << 8) | commandApdu.getP2();
        switch (p1p2) {
            case 0x9E9A:
                builder.append(" [COMPUTE DIGITAL SIGNATURE]");
                return;
            case 0x8086:
                builder.append(" [DECIPHER]");
                return;
        }
        builder.append(" !! INVALID P1P2 0x").append(Integer.toHexString(p1p2)).append(" FOR PSO !!");
    }

    private void describeVerifyP1P2(CommandApdu commandApdu, StringBuilder builder) {
        switch (commandApdu.getP2()) {
            case 0x81:
                builder.append(" [PW1/sig]");
                return;
            case 0x82:
                builder.append(" [PW1/other]");
                return;
            case 0x83:
                builder.append(" [PW3]");
                return;
        }
        int p1p2 = (commandApdu.getP1() << 8) | commandApdu.getP2();
        builder.append(" !! INVALID P1P2 0x").append(Integer.toHexString(p1p2)).append(" FOR PSO !!");
    }

    private void describeDataObjectP1P2(CommandApdu commandApdu, StringBuilder builder) {
        int p1p2 = (commandApdu.getP1() << 8) | commandApdu.getP2();
        switch (p1p2) {
            case OpenPgpCommandApduFactory.DO_GET_DATA_CARD_HOLDER_CERT:
                builder.append(" [cardholder cert]");
                break;
            case OpenPgpCommandApduFactory.DO_GET_DATA_APPLICATION_RELATED_DATA:
                builder.append(" [application related]");
                break;
            case OpenPgpCommandApduFactory.DO_GET_DATA_URL:
                builder.append(" [url]");
                break;
            case OpenPgpCommandApduFactory.DO_GET_DATA_CARDHOLDER_RELATED_DATA:
                builder.append(" [cardholder related]");
                break;
            default:
                builder.append(" [unknown DO 0x").append(Integer.toHexString(p1p2)).append("]");
                break;
        }
    }

}
