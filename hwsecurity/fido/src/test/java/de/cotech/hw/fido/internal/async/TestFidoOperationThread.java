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

package de.cotech.hw.fido.internal.async;


import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import android.os.Handler;

import de.cotech.hw.fido.internal.FakeU2fFidoAppletConnection;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


@SuppressWarnings("unused")
class TestFidoOperationThread extends FidoOperationThread<Integer> {
    private final CountDownLatch countDownLatch;
    private final CountDownLatch delayLatch;

    TestFidoOperationThread() throws Exception {
        this(FakeU2fFidoAppletConnection.create().connection, new Handler(), null);
    }

    TestFidoOperationThread(CountDownLatch delayLatch) throws Exception {
        this(FakeU2fFidoAppletConnection.create().connection, new Handler(), delayLatch);
    }

    private TestFidoOperationThread(FidoU2fAppletConnection fidoU2fAppletConnection, Handler handler,
            CountDownLatch delayLatch) {
        super(fidoU2fAppletConnection, handler, 10);
        this.countDownLatch = new CountDownLatch(3);
        this.delayLatch = delayLatch;
        setFidoAsyncOperationManager(Mockito.mock(FidoAsyncOperationManager.class));
    }

    @Override
    void prepareOperation() {
        countDownLatch.countDown();
    }

    @Override
    Integer performOperation() throws InterruptedException {
        if (delayLatch != null) {
            delayLatch.await();
        }
        countDownLatch.countDown();
        return 5;
    }

    @Override
    void deliverResponse(Integer response) {
        countDownLatch.countDown();
        assertEquals(5, response.intValue());
    }

    @Override
    void deliverIoException(IOException e) {
        fail();
    }

    void assertLatchOk() {
        try {
            assertTrue("Timeout waiting for thread!", countDownLatch.await(500, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail("got interrupted unexpectedly");
        }
    }

    void assertLatchTimeout() {
        try {
            assertFalse("Thread unexpectedly returned!", countDownLatch.await(500, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail("got interrupted unexpectedly");
        }
    }
}
