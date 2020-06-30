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

package de.cotech.hw.fido;


import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.exceptions.InsNotSupportedException;
import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido.internal.FakeU2fFidoAppletConnection;
import de.cotech.hw.fido.internal.async.FidoAsyncOperationManager;
import de.cotech.hw.fido.internal.async.FidoAsyncOperationManagerUtil;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLooper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


@SuppressWarnings("WeakerAccess")
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 24)
public class FidoSecurityKeyTest {
    static final String FIDO_APP_ID = "https://fido-login.example.com/app-id.json";
    static final String FACET_ID = "android:apk-key-hash:Oo/JkRFBKdDfHqZ3wWXCC3GrlKk";

    static final String REGISTER_CHALLENGE = "eggc8lflivyKtxl3zVRXRQ";
    static final String AUTH_CHALLENGE = "zsXiC59rARVhgrU80i462Q";

    static final byte[] KEY_HANDLE = Hex.decodeHexOrFail("49e0a7716673b4627f272ced3f52c511f1671a6e5e05d56d28681f8b54c9240f28960fc90df6b036fa934e3d5bed75a7ffbb4ea5f78d4e6daf0e78bdbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee9ff2598fa0");
    static final byte[] KEY_HANDLE_BAD = Hex.decodeHexOrFail("1047cad7b407bf7bf0a7b30bf7ddcb07ad7b21384732487237bdf0a87b21407bae19438b019843bc108bd018ba9eff9813ba08cde08341b0dba983ffbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee939201aefa");

    static final String AUTH_EXPECTED_CHALLENGE = "00020300a156493b7586f818b6d46127c0439232912d5e5a9ed526b864a228bb7c63c1437cabc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881f7b5494dcb6049e0a7716673b4627f272ced3f52c511f1671a6e5e05d56d28681f8b54c9240f28960fc90df6b036fa934e3d5bed75a7ffbb4ea5f78d4e6daf0e78bdbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee9ff2598fa0";
    static final String AUTH_EXPECTED_CHALLENGE_BAD = "00020300a156493b7586f818b6d46127c0439232912d5e5a9ed526b864a228bb7c63c1437cabc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881f7b5494dcb601047cad7b407bf7bf0a7b30bf7ddcb07ad7b21384732487237bdf0a87b21407bae19438b019843bc108bd018ba9eff9813ba08cde08341b0dba983ffbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee939201aefa";

    static final String AUTH_REPLY_OK = "0100001c243045022069d5c931a1644376c9d7bf6a7892f7409158b62ea74a04333d799077202cb959022100f74dcb8f2e32b74ca4b94f03259c74ff11ea7936e22a32806290502c56c998af9000";
    static final String AUTH_REPLY_EXPECTED = "0100001c243045022069d5c931a1644376c9d7bf6a7892f7409158b62ea74a04333d799077202cb959022100f74dcb8f2e32b74ca4b94f03259c74ff11ea7936e22a32806290502c56c998af";

    static final String REGISTER_EXPECTED_CHALLENGE = "00010300405232486109f3e7a727481748b19c51b9664e2442f9403d8b6f13e0d85979bc57abc34b4eb978b911e55240f345649cd3d7e8b583fbe066984d9881f7b5494dcb";
    static final String REGISTER_REPLY_OK = "0504c55aa14193505c47fb2532a9c06deac896a149a172e2872c8392eb545d8658bc0229b80b6eabd8d61041fbaf1050947e3d276ffa17004819c96e48248b9346af6049e0a7716673b4627f272ced3f52c511f1671a6e5e05d56d28681f8b54c9240f28960fc90df6b036fa934e3d5bed75a7ffbb4ea5f78d4e6daf0e78bdbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee9ff2598fa0308201663082010ba003020102020900d79549bd1a67174f300a06082a8648ce3d04030230173115301306035504030c0c4654204649444f20303230303020170d3137303632303030303030305a180f32303430303530313030303030305a301f311d301b06035504030c144654204649444f203034333030313333433841383059301306072a8648ce3d020106082a8648ce3d03010703420004c0ce4c2b00a6311a8564de7aebfbdbd064c65c7d3085e48a885b96d11ad9e0e89a279e2c58dc079364f7dbfd1b28d6683694d55bea9d4f6d1cb7eee9492e0501a3363034301d0603551d0e04160414f4b64a68c334e901b8e23c6e66e6866c31931f5d3013060b2b0601040182e51c020101040403020430300a06082a8648ce3d0403020349003046022100c19418a6c96f6ca8699bacb556775fc067c608f39dc508226aa1012b3e9c9c670221008dd32442c7fbc7699b3dab3238938fa1a202f00323cfbae95eca414535a486d93044022038001ae6faa46eb93ea17b388a1d28102256ffe83871b6af3e5dfd3d57562b60022032ab6db39ad3d1c5e6cb750de199c42ee94df4851061912e7beb1eedda3c7b6b9000";
    static final String REGISTER_REPLY_EXPECTED = "0504c55aa14193505c47fb2532a9c06deac896a149a172e2872c8392eb545d8658bc0229b80b6eabd8d61041fbaf1050947e3d276ffa17004819c96e48248b9346af6049e0a7716673b4627f272ced3f52c511f1671a6e5e05d56d28681f8b54c9240f28960fc90df6b036fa934e3d5bed75a7ffbb4ea5f78d4e6daf0e78bdbb4b88b9cd4c6d0157ea5876c0c45c575e99c5e928a405bba76b780a1ec3ee9ff2598fa0308201663082010ba003020102020900d79549bd1a67174f300a06082a8648ce3d04030230173115301306035504030c0c4654204649444f20303230303020170d3137303632303030303030305a180f32303430303530313030303030305a301f311d301b06035504030c144654204649444f203034333030313333433841383059301306072a8648ce3d020106082a8648ce3d03010703420004c0ce4c2b00a6311a8564de7aebfbdbd064c65c7d3085e48a885b96d11ad9e0e89a279e2c58dc079364f7dbfd1b28d6683694d55bea9d4f6d1cb7eee9492e0501a3363034301d0603551d0e04160414f4b64a68c334e901b8e23c6e66e6866c31931f5d3013060b2b0601040182e51c020101040403020430300a06082a8648ce3d0403020349003046022100c19418a6c96f6ca8699bacb556775fc067c608f39dc508226aa1012b3e9c9c670221008dd32442c7fbc7699b3dab3238938fa1a202f00323cfbae95eca414535a486d93044022038001ae6faa46eb93ea17b388a1d28102256ffe83871b6af3e5dfd3d57562b60022032ab6db39ad3d1c5e6cb750de199c42ee94df4851061912e7beb1eedda3c7b6b";

    static final String REPLY_PRESENCE_REQUIRED = "6985";
    static final String REPLY_WRONG_KEY_HANDLE = "6A80";

    FidoSecurityKey fidoSecurityKey;
    FakeU2fFidoAppletConnection fakeFidoConnection;
    FidoAsyncOperationManager fidoAsyncOperationManager;

    @Before
    public void setup() throws Exception {
        fakeFidoConnection = FakeU2fFidoAppletConnection.create();
        fidoAsyncOperationManager = new FidoAsyncOperationManager();
        fidoSecurityKey = new FidoSecurityKey(
                new SecurityKeyManagerConfig.Builder().build(),
                fakeFidoConnection.connection, null, fidoAsyncOperationManager
        );
    }

    @Test
    public void register() throws IOException {
        FidoRegisterRequest fidoRegisterRequest = FidoRegisterRequest.create(FIDO_APP_ID, FACET_ID, REGISTER_CHALLENGE);
        fakeFidoConnection.expect(REGISTER_EXPECTED_CHALLENGE, REGISTER_REPLY_OK);

        FidoRegisterResponse registerResponse = fidoSecurityKey.register(fidoRegisterRequest);

        assertEquals(REGISTER_REPLY_EXPECTED, Hex.encodeHexString(registerResponse.getBytes()));
    }

    @Test(expected = FidoPresenceRequiredException.class)
    public void register_presenceRequired() throws IOException {
        FidoRegisterRequest fidoRegisterRequest = FidoRegisterRequest.create(FIDO_APP_ID, FACET_ID, REGISTER_CHALLENGE);
        fakeFidoConnection.expect(REGISTER_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);

        fidoSecurityKey.register(fidoRegisterRequest);
    }

    @Test
    public void registerAsync() throws Exception {
        FidoRegisterRequest registerRequest = FidoRegisterRequest.create(FIDO_APP_ID, FACET_ID, REGISTER_CHALLENGE);
        fakeFidoConnection.expect(REGISTER_EXPECTED_CHALLENGE, REGISTER_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.registerAsync(registerRequest,
                new FidoRegisterCallback() {
                    @Override
                    public void onRegisterResponse(FidoRegisterResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        countDownLatch.countDown();
                    }
                },null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void registerAsync_withPresenceRequired() throws Exception {
        FidoRegisterRequest registerRequest = FidoRegisterRequest.create(FIDO_APP_ID, FACET_ID, REGISTER_CHALLENGE);
        fakeFidoConnection.expect(REGISTER_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);
        fakeFidoConnection.expect(REGISTER_EXPECTED_CHALLENGE, REGISTER_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.registerAsync(registerRequest,
                new FidoRegisterCallback() {
                    @Override
                    public void onRegisterResponse(FidoRegisterResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        countDownLatch.countDown();
                    }
                },null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void authenticate() throws Exception {
        FidoAuthenticateRequest authenticateRequest =
                FidoAuthenticateRequest.create(FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        FidoAuthenticateResponse authResponse = fidoSecurityKey.authenticate(authenticateRequest);

        assertEquals(AUTH_REPLY_EXPECTED, Hex.encodeHexString(authResponse.getBytes()));
    }

    @Test
    public void authenticate_multipleKeyHandles() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        FidoAuthenticateResponse authResponse = fidoSecurityKey.authenticate(authenticateRequest);

        assertEquals(AUTH_REPLY_EXPECTED, Hex.encodeHexString(authResponse.getBytes()));
    }

    @Test(expected = FidoPresenceRequiredException.class)
    public void authenticate_multipleKeyHandles_presenceCheck() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);

        fidoSecurityKey.authenticate(authenticateRequest);
    }

    @Test(expected = FidoWrongKeyHandleException.class)
    public void authenticate_multipleKeyHandles_allWrongKeyHandle() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_WRONG_KEY_HANDLE);

        fidoSecurityKey.authenticate(authenticateRequest);
    }

    @Test(expected = FidoPresenceRequiredException.class)
    public void authenticate_presenceRequired() throws Exception {
        FidoAuthenticateRequest authenticateRequest =
                FidoAuthenticateRequest.create(FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, "6985");

        fidoSecurityKey.authenticate(authenticateRequest);
    }

    @Test
    public void authenticateAsync() throws Exception {
        FidoAuthenticateRequest authenticateRequest =
                FidoAuthenticateRequest.create(FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        fail("Unexpected IOException!");
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void authenticateAsync_withPresence() throws Exception {
        FidoAuthenticateRequest authenticateRequest =
                FidoAuthenticateRequest.create(FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        fail("Unexpected IOException!");
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void authenticateAsync_multipleKeyHandles() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        fail("Unexpected IOException!");
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void authenticateAsync_multipleKeyHandles_withPresence() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_PRESENCE_REQUIRED);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, AUTH_REPLY_OK);

        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        assertNotNull(response);
                        countDownLatch.countDown();
                    }

                    @Override
                    public void onIoException(IOException e) {
                        fail("Unexpected IOException!");
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
    }

    @Test
    public void authenticateAsync_wrongKeyHandle() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, Arrays.asList(KEY_HANDLE_BAD, KEY_HANDLE));
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE_BAD, REPLY_WRONG_KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, REPLY_WRONG_KEY_HANDLE);

        IOException[] thrownException = new IOException[1];
        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        fail("Unexpectedly got auth response!");
                    }

                    @Override
                    public void onIoException(IOException e) {
                        thrownException[0] = e;
                        countDownLatch.countDown();
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
        assertEquals(FidoWrongKeyHandleException.class, thrownException[0].getClass());
    }

    @Test
    public void authenticateAsync_insNotSupported() throws Exception {
        FidoAuthenticateRequest authenticateRequest = FidoAuthenticateRequest.create(
                FIDO_APP_ID, FACET_ID, AUTH_CHALLENGE, KEY_HANDLE);
        fakeFidoConnection.expect(AUTH_EXPECTED_CHALLENGE, "6D00");

        IOException[] thrownException = new IOException[1];
        CountDownLatch countDownLatch = new CountDownLatch(1);
        fidoSecurityKey.authenticateAsync(authenticateRequest,
                new FidoAuthenticateCallback() {
                    @Override
                    public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                        fail("Unexpectedly got auth response!");
                    }

                    @Override
                    public void onIoException(IOException e) {
                        thrownException[0] = e;
                        countDownLatch.countDown();
                    }
                }, null);
        FidoAsyncOperationManagerUtil.joinRunningThread(fidoAsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        assertTrue(countDownLatch.await(1, TimeUnit.SECONDS));
        assertEquals(InsNotSupportedException.class, thrownException[0].getClass());
    }
}