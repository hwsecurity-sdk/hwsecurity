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

import android.os.Handler;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.UiThread;
import androidx.annotation.WorkerThread;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.OnLifecycleEvent;

import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.fido.exceptions.FidoPresenceRequiredException;
import de.cotech.hw.fido.internal.FidoU2fAppletConnection;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
abstract class FidoOperationThread<T> extends Thread implements LifecycleObserver {
    private FidoAsyncOperationManager fidoAsyncOperationManager;
    private final Handler handler;
    private final int presenceCheckDelayMs;
    final FidoU2fAppletConnection fidoU2fAppletConnection;

    FidoOperationThread(FidoU2fAppletConnection fidoU2fAppletConnection, Handler handler, int presenceCheckDelayMs) {
        this.fidoU2fAppletConnection = fidoU2fAppletConnection;
        this.handler = handler;
        this.presenceCheckDelayMs = presenceCheckDelayMs;
    }

    @WorkerThread
    abstract void prepareOperation() throws InterruptedException;
    @WorkerThread
    abstract T performOperation() throws IOException, InterruptedException;
    @UiThread
    abstract void deliverResponse(T response);
    @UiThread
    abstract void deliverIoException(IOException e);

    void setFidoAsyncOperationManager(FidoAsyncOperationManager fidoAsyncOperationManager) {
        this.fidoAsyncOperationManager = fidoAsyncOperationManager;
    }

    @Override
    public void run() {
        try {
            prepareOperation();
        } catch (InterruptedException e) {
            fidoAsyncOperationManager.clearAsyncOperation(false, this);
            return;
        }
        while (!isInterrupted() && fidoU2fAppletConnection.isConnected()) {
            try {
                T response = performOperation();
                postToHandler(() -> deliverResponse(response));
                break;
            } catch (InterruptedException e) {
                HwTimber.e("Fido operation was interrupted");
                break;
            } catch (SecurityKeyDisconnectedException e) {
                HwTimber.e("Transport gone during fido operation");
                break;
            } catch (FidoPresenceRequiredException e) {
                try {
                    Thread.sleep(presenceCheckDelayMs);
                } catch (InterruptedException e1) {
                    break;
                }
            } catch (IOException e) {
                if (e.getCause() instanceof InterruptedException) {
                    HwTimber.e("Fido operation was interrupted");
                    break;
                }
                postToHandler(() -> deliverIoException(e));
                break;
            }
        }
        fidoAsyncOperationManager.clearAsyncOperation(false, this);
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
            fidoAsyncOperationManager.clearAsyncOperation(true, this);
        }
    }
}
