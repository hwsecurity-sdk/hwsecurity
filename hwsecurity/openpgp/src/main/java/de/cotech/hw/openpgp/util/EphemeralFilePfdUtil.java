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


import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import android.content.Context;
import android.os.Handler;
import android.os.ParcelFileDescriptor;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.openpgp.util.ParcelFileDescriptorUtil.InputStreamProvider;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
class EphemeralFilePfdUtil {
    private static final int MAX_CACHED_FDS = 5;

    private final Handler handler;
    private final File displayCacheDir;
    private final ConcurrentHashMap<String, List<ParcelFileDescriptor>> fileDescriptorCache = new ConcurrentHashMap<>();

    EphemeralFilePfdUtil(Context context) {
        this.handler = new Handler(context.getMainLooper());
        this.displayCacheDir = new File(context.getCacheDir(), "fd_cache");
    }

    private void ensureCacheDir() throws IOException {
        if (!displayCacheDir.isDirectory()) {
            if (!displayCacheDir.mkdir()) {
                throw new IOException("Failed to create temporary directory!");
            }
        }
    }

    ParcelFileDescriptor loadDataToFileDescriptor(String id, InputStreamProvider inputStreamProvider)
            throws IOException {
        List<ParcelFileDescriptor> fdList;
        synchronized (fileDescriptorCache) {
            if (!fileDescriptorCache.containsKey(id)) {
                fileDescriptorCache.put(id, new ArrayList<>());
            }
            fdList = fileDescriptorCache.get(id);
        }
        // noinspection SynchronizationOnLocalVariableOrMethodParameter, fdList comes from fileDescriptorCache
        synchronized (fdList) {
            if (fdList.isEmpty()) {
                HwTimber.d("Decrypting data for %s", id);
                fillCachedFdList(id, fdList, inputStreamProvider);
            }
            HwTimber.d("Using cached file descriptor (%d/%d left) for %s", fdList.size(), MAX_CACHED_FDS, id);
            return fdList.remove(0);
        }
    }

    private void fillCachedFdList(String id, List<ParcelFileDescriptor> fdList, InputStreamProvider inputStreamProvider)
            throws IOException {
        ensureCacheDir();
        File cacheFile = File.createTempFile(id, null, displayCacheDir);
        try {
            readInputStreamToFile(inputStreamProvider.getInputStream(), cacheFile);

            try {
                for (int i = 0; i < MAX_CACHED_FDS; i++) {
                    ParcelFileDescriptor pfd =
                            ParcelFileDescriptor.open(cacheFile, ParcelFileDescriptor.MODE_READ_ONLY);
                    fdList.add(pfd);
                }
            } finally {
                postCachedFdCleanupJob(id, fdList);
            }
        } finally {
            if (!cacheFile.delete()) {
                HwTimber.e("Failed to delete temp file: %s", cacheFile.getCanonicalPath());
            }
        }
    }

    private void postCachedFdCleanupJob(String id, List<ParcelFileDescriptor> fdList) {
        handler.postDelayed(() -> {
            synchronized (fdList) {
                if (fdList.isEmpty()) {
                    HwTimber.d("Clearing %d/%d cached file descriptors for %s", fdList.size(), MAX_CACHED_FDS, id);
                    for (ParcelFileDescriptor fd : fdList) {
                        try {
                            fd.close();
                        } catch (IOException e) {
                            HwTimber.e(e, "Ignoring exception from ParcelFileDescriptor.close()");
                        }
                    }
                }
                fileDescriptorCache.remove(id, fdList);
            }
        }, 1000);
    }

    private void readInputStreamToFile(InputStream inputStream, File cacheFile) throws IOException {
        BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(cacheFile));
        byte[] buf = new byte[256];
        int len;
        while ((len = inputStream.read(buf)) > 0) {
            outputStream.write(buf, 0, len);
        }
    }
}
