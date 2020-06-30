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


import java.io.IOException;

import android.os.Handler;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.OnLifecycleEvent;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.fido2.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido2.internal.Fido2AppletConnection;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
abstract class Fido2OperationThread<T> extends Thread implements LifecycleObserver {
    private Fido2AsyncOperationManager fido2AsyncOperationManager;
    private final Handler handler;
    private final int presenceCheckDelayMs;
    final Fido2AppletConnection fido2AppletConnection;

    Fido2OperationThread(Fido2AppletConnection fido2AppletConnection, Handler handler, int presenceCheckDelayMs) {
        this.fido2AppletConnection = fido2AppletConnection;
        this.handler = handler;
        this.presenceCheckDelayMs = presenceCheckDelayMs;
    }

    @WorkerThread
    void prepareOperation() throws InterruptedException {

    }

    @WorkerThread
    abstract T performOperation() throws IOException, InterruptedException;
    @UiThread
    abstract void deliverResponse(T response);
    @UiThread
    abstract void deliverIoException(IOException e);

    void setFido2AsyncOperationManager(Fido2AsyncOperationManager fido2AsyncOperationManager) {
        this.fido2AsyncOperationManager = fido2AsyncOperationManager;
    }

    @Override
    public void run() {
        try {
            prepareOperation();
        } catch (InterruptedException e) {
            fido2AsyncOperationManager.clearAsyncOperation(false, this);
            return;
        }
        while (!isInterrupted() && fido2AppletConnection.isConnected()) {
            try {
                T response = performOperation();
                postToHandler(() -> deliverResponse(response));
                break;
            } catch (InterruptedException e) {
                HwTimber.e("Fido 2 operation was interrupted");
                break;
            } catch (SecurityKeyDisconnectedException e) {
                HwTimber.e("Transport gone during fido 2 operation");
                break;
            } catch (FidoPresenceRequiredException e) {
                try {
                    Thread.sleep(presenceCheckDelayMs);
                } catch (InterruptedException e1) {
                    break;
                }
            } catch (IOException e) {
                if (e.getCause() instanceof InterruptedException) {
                    HwTimber.e("Fido 2 operation was interrupted");
                    break;
                }
                postToHandler(() -> deliverIoException(e));
                break;
            }
        }
        fido2AsyncOperationManager.clearAsyncOperation(false, this);
    }

    private void postToHandler(Runnable runnable) {
        if (isInterrupted()) {
            return;
        }
        handler.post(() -> {
            if (!isInterrupted()) {
                runnable.run();
            }
        });
    }

    @OnLifecycleEvent(Event.ON_STOP)
    public void onDestroy() {
        if (isAlive() && !isInterrupted()) {
            fido2AsyncOperationManager.clearAsyncOperation(true, this);
        }
    }
}
