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

package de.cotech.hw.openpgp.util;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build.VERSION_CODES;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.MemoryFile;
import android.os.ParcelFileDescriptor;
import android.os.ProxyFileDescriptorCallback;
import android.os.SystemClock;
import android.os.storage.StorageManager;
import android.system.ErrnoException;
import android.system.OsConstants;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.openpgp.util.ParcelFileDescriptorUtil.InputStreamProvider;
import de.cotech.hw.util.HwTimber;


@TargetApi(VERSION_CODES.O)
@RestrictTo(Scope.LIBRARY_GROUP)
class MemoryFilePfdUtil {
    private final Handler handler;
    private final StorageManager storageManager;
    private final ConcurrentHashMap<String, MemoryFile> memoryFileCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<MemoryFile, AtomicInteger> memoryFileRefCounters = new ConcurrentHashMap<>();

    MemoryFilePfdUtil(Context context) {
        this.handler = new Handler(context.getMainLooper());
        this.storageManager = (StorageManager) context.getSystemService(Context.STORAGE_SERVICE);
    }

    ParcelFileDescriptor loadDataToFileDescriptorCallback(String cacheId, int plaintextLength,
            InputStreamProvider inputStreamProvider)
            throws IOException {
        MemoryFile memoryFile = obtainRefcountedMemoryFile(cacheId, plaintextLength, inputStreamProvider);

        HandlerThread handlerThread = new HandlerThread("ProxyFileDescriptorHandlerThread");
        handlerThread.start();
        Handler pfdCallbackHandler = new Handler(handlerThread.getLooper());
        ProxyFileDescriptorCallback pfdCallback = new ProxyFileDescriptorCallback() {
            public long onGetSize() {
                return (long) plaintextLength;
            }

            public int onRead(long offset, int size, byte[] data) throws ErrnoException {
                int bytesLeft = (plaintextLength - (int) offset);
                int bytesToRead;
                if (size + offset < plaintextLength) {
                    bytesToRead = size;
                } else {
                    bytesToRead = bytesLeft;
                }

                try {
                    return memoryFile.readBytes(data, (int) offset, 0, bytesToRead);
                } catch (IOException e) {
                    throw new ErrnoException("onRead", OsConstants.EIO);
                }
            }

            public void onRelease() {
                releaseRefcountedMemoryFile(cacheId, memoryFile);
                pfdCallbackHandler.getLooper().quitSafely();
            }
        };
        return storageManager
                .openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY, pfdCallback, pfdCallbackHandler);
    }

    private void releaseRefcountedMemoryFile(String cacheId, MemoryFile memoryFile) {
        synchronized (memoryFileCache) {
            AtomicInteger refCount = memoryFileRefCounters.get(memoryFile);
            int refs = refCount.decrementAndGet();
            if (refs == 0) {
                HwTimber.d("Clearing memory file for %s", cacheId);
                memoryFile.close();
                memoryFileCache.remove(cacheId, memoryFile);
                memoryFileRefCounters.remove(memoryFile);
            } else {
                HwTimber.d("Keeping memory file for %s (%d refs left)", cacheId, refs);
            }
        }
    }

    private MemoryFile obtainRefcountedMemoryFile(String cacheId, int plaintextLength,
            InputStreamProvider inputStreamProvider)
            throws IOException {
        synchronized (memoryFileCache) {
            MemoryFile memoryFile = memoryFileCache.get(cacheId);
            if (memoryFile != null) {
                memoryFileRefCounters.get(memoryFile).incrementAndGet();
                HwTimber.d("Using cached memory file for %s", cacheId);
                return memoryFile;
            }

            HwTimber.d("Decrypting to memory file for %s", cacheId);
            final MemoryFile newMemoryFile = copyToMemoryFile(inputStreamProvider.getInputStream(), plaintextLength);
            memoryFileCache.put(cacheId, newMemoryFile);
            AtomicInteger refCount = new AtomicInteger(2);
            memoryFileRefCounters.put(newMemoryFile, refCount);

            handler.postDelayed(() -> releaseRefcountedMemoryFile(cacheId, newMemoryFile), 2000);

            return newMemoryFile;
        }
    }

    private MemoryFile copyToMemoryFile(InputStream inputStream, int length) throws IOException {
        long startTime = SystemClock.elapsedRealtime();
        MemoryFile memoryFile = new MemoryFile(null, length);

        OutputStream outputStream = memoryFile.getOutputStream();

        byte[] buf = new byte[256];
        int len;
        int totalLen = 0;
        while ((len = inputStream.read(buf)) > 0) {
            outputStream.write(buf, 0, len);
            totalLen += len;
        }
        HwTimber.d("Loaded %d kb to memory file in %dms", totalLen / 1024,
                SystemClock.elapsedRealtime() - startTime);
        if (length != totalLen) {
            HwTimber.w("Length written to file didn't match expected (%d vs %d)", length, totalLen);
        }

        return memoryFile;
    }
}
