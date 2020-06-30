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
public class RegisterOpTest {
    static final byte[] CHALLENGE_PARAM = Hex.decodeHexOrFail("d05cf90f8fb8465872893527acc13581d955240181ffed27ddca929a8209b14c");
    static final byte[] APPLICATION_PARAM = Hex.decodeHexOrFail("abc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881f7b5494dcb");
    static final String REGISTER_REPLY_PRESENCE_REQUIRED = "6985";

    static final String REGISTER_EXPECTED_CHALLENGE =
            "0001030040d05cf90f8fb8465872893527acc13581d955240181ffed27ddca92" +
                    "9a8209b14cabc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881" +
                    "f7b5494dcb";
    static final String REGISTER_REPLY_OK =
            "050477b7154009aa3430c43bb2a500ff427577050c7513071b5f913b59944cdf" +
                    "4b08c189506a6902e562daf330544fc0080bb46b1fb90e2dc51fc59c2d44a18226d9" +
                    "409111966c9e43e0245440325ab0c99d77d5c0ed35db0579fe2de080776c92c797ff" +
                    "edcd50eb8723a5a3354e654887a7ced66598994bbc079abde76bd041bb92da308202" +
                    "4f30820137a00302010202041236d17f300d06092a864886f70d01010b0500302e31" +
                    "2c302a0603550403132359756269636f2055324620526f6f74204341205365726961" +
                    "6c203435373230303633313020170d3134303830313030303030305a180f32303530" +
                    "303930343030303030305a3031312f302d06035504030c2659756269636f20553246" +
                    "2045452053657269616c203233393235373334313033323431303837305930130607" +
                    "2a8648ce3d020106082a8648ce3d03010703420004d365a91e5e99e0d5b439c0d9af" +
                    "bb87f4058e47dd12b144edb14d2b33f8d35c1513e40d79f0f999abe23671959381c9" +
                    "dc2b07858b82ac63476204ccf734d6ae21a33b3039302206092b0601040182c40a02" +
                    "0415312e332e362e312e342e312e34313438322e312e353013060b2b0601040182e5" +
                    "1c020101040403020520300d06092a864886f70d01010b05000382010100221b9bb3" +
                    "b27224f13ebea322f0351eaf464966a36f7269857c8e23f9e505b55275dd4e41223e" +
                    "7f2611091469cf929fa5263e6cc77681b2486daaf41fb1cfabe85508f13f6750f6c8" +
                    "1b29de601b5e7208bbfa6476e564a91d7d64ab524ad04ebb5ace218b1526f171f87c" +
                    "def52398e8432c50b9bf1578197ab6ebbe32abd1769338389c24b8c97acee3f1bc61" +
                    "6476caf42f1367df2928d02655c63b9d3cd0ab69b6996fe573788b9952f802ab4f94" +
                    "1155b109dc1e20ec6d2542175857eeabe19b478a5f2617860d319d3e45a60fc40698" +
                    "35690561dcce6426887506d745979f8067db3148800b683058dedf88f1d5f5ebbcd8" +
                    "d632a46537d8e8a31bd063846b7f3044022012d00c7b664a40b4cee0ab881f021b63" +
                    "7fd4708a876468acaeea0d0fea55c0c8022054bdddfb76e3ffa501a0450d87be2cc3" +
                    "2ec8a6e1f833cef7bd1359f0f86a10969000";

    FakeU2fFidoAppletConnection fakeConnection;
    RegisterOp registerOp;

    @Before
    public void setup() throws Exception {
        fakeConnection = FakeU2fFidoAppletConnection.create();
        registerOp = RegisterOp.create(fakeConnection.connection);
    }

    @Test
    public void register() throws Exception {
        fakeConnection.expect(REGISTER_EXPECTED_CHALLENGE, REGISTER_REPLY_OK);

        registerOp.register(CHALLENGE_PARAM, APPLICATION_PARAM);
    }

    @Test(expected = FidoPresenceRequiredException.class)
    public void register_userPresenceUnavailable() throws Exception {
        fakeConnection.expect(REGISTER_EXPECTED_CHALLENGE, REGISTER_REPLY_PRESENCE_REQUIRED);

        registerOp.register(CHALLENGE_PARAM, APPLICATION_PARAM);
    }
}
