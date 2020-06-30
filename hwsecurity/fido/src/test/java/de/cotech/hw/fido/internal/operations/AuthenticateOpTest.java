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

package de.cotech.hw.fido.internal.operations;


import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.internal.FakeU2fFidoAppletConnection;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;


@SuppressWarnings({ "WeakerAccess", "SameParameterValue" })
public class AuthenticateOpTest {
    static final byte[] CHALLENGE_PARAM = Hex.decodeHexOrFail("d05cf90f8fb8465872893527acc13581d955240181ffed27ddca929a8209b14c");
    static final byte[] APPLICATION_PARAM = Hex.decodeHexOrFail("abc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881f7b5494dcb");
    static final String REPLY_PRESENCE_REQUIRED = "6985";

    static final String EXPECTED_CHALLENGE =
            "0002030081d05cf90f8fb8465872893527acc13581d955240181ffed27ddca92" +
                    "9a8209b14cabc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881" +
                    "f7b5494dcb409111966c9e43e0245440325ab0c99d77d5c0ed35db0579fe2de0" +
                    "80776c92c797ffedcd50eb8723a5a3354e654887a7ced66598994bbc079abde7" +
                    "6bd041bb92da";
    static final String REPLY_OK =
            "010000001d304502202108381d65d73659e0584287fab410628d3d771dcc685e" +
                    "53f29e459c14ab2943022100f058d95f04dbe2685b43f79cc26e4df0d117fee3" +
                    "8352c73385e53348ed58f3309000";
    static final byte[] KEY_HANDLE = Hex.decodeHexOrFail(
            "9111966c9e43e0245440325ab0c99d77d5c0ed35db0579fe2de080776c92c797" +
                    "ffedcd50eb8723a5a3354e654887a7ced66598994bbc079abde76bd041bb92da");

    AuthenticateOp authenticateOp;
    FakeU2fFidoAppletConnection fakeConnection;

    @Before
    public void setup() throws Exception {
        fakeConnection = FakeU2fFidoAppletConnection.create();
        authenticateOp = AuthenticateOp.create(fakeConnection.connection);
    }

    @Test
    public void authenticate() throws Exception {
        fakeConnection.expect(EXPECTED_CHALLENGE, REPLY_OK);

        authenticateOp.authenticate(CHALLENGE_PARAM, APPLICATION_PARAM, KEY_HANDLE);
    }

    @Test(expected = FidoPresenceRequiredException.class)
    public void authenticate_userPresenceUnavailable() throws Exception {
        fakeConnection.expect(EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);

        authenticateOp.authenticate(CHALLENGE_PARAM, APPLICATION_PARAM, KEY_HANDLE);
    }
}