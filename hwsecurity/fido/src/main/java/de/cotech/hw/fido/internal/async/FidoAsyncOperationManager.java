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


import androidx.annotation.AnyThread;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;
import androidx.lifecycle.LifecycleOwner;
import de.cotech.hw.fido.internal.utils.AndroidUtils;


@RestrictTo(Scope.LIBRARY_GROUP)
public class FidoAsyncOperationManager {
    private final Object asyncOperationLock;
    @VisibleForTesting
    FidoOperationThread<?> asyncOperationThread;

    public FidoAsyncOperationManager() {
        asyncOperationLock = new Object();
    }

    @AnyThread
    public void startAsyncOperation(LifecycleOwner lifecycleOwner, FidoOperationThread<?> operationThread) {
        synchronized (asyncOperationLock) {
            if (asyncOperationThread != null) {
                asyncOperationThread.interrupt();
                asyncOperationThread = null;
            }

            asyncOperationThread = operationThread;
            asyncOperationThread.setFidoAsyncOperationManager(this);
            asyncOperationThread.start();
            AndroidUtils.addLifecycleObserver(lifecycleOwner, asyncOperationThread);
        }
    }

    @AnyThread
    public void clearAsyncOperation() {
        clearAsyncOperation(true, null);
    }

    @AnyThread
    void clearAsyncOperation(boolean interrupt, Thread specificThread) {
        synchronized (asyncOperationLock) {
            if (specificThread != null && asyncOperationThread != specificThread) {
                if (interrupt) {
                    specificThread.interrupt();
                }
                return;
            }
            if (asyncOperationThread != null && asyncOperationThread.isAlive() && interrupt) {
                asyncOperationThread.interrupt();
            }
            asyncOperationThread = null;
        }
    }
}
