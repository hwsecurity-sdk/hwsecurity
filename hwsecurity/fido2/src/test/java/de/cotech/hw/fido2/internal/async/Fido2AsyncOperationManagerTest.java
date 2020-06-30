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

package de.cotech.hw.fido2.internal.async;


import java.util.concurrent.CountDownLatch;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLooper;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


@RunWith(RobolectricTestRunner.class)
@Config(sdk = 24)
public class Fido2AsyncOperationManagerTest {

    private Fido2AsyncOperationManager fido2AsyncOperationManager;

    @Before
    public void setup() {
        fido2AsyncOperationManager = new Fido2AsyncOperationManager();
    }

    @Test
    public void startAsyncOperation() throws Exception {
        TestFido2OperationThread thread = new TestFido2OperationThread();
        fido2AsyncOperationManager.startAsyncOperation(null, thread);
        FidoAsyncOperationManagerUtil.joinRunningThread(fido2AsyncOperationManager);
        assertTrue(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
        thread.assertLatchOk();
    }

    @Test
    public void startAsyncOperation_thenClear() throws Exception {
        CountDownLatch delayLatch = new CountDownLatch(1);
        TestFido2OperationThread thread = new TestFido2OperationThread(delayLatch);
        fido2AsyncOperationManager.startAsyncOperation(null, thread);
        fido2AsyncOperationManager.clearAsyncOperation();
        FidoAsyncOperationManagerUtil.joinRunningThread(fido2AsyncOperationManager);
        assertFalse(ShadowLooper.getShadowMainLooper().getScheduler().runOneTask());
    }


}