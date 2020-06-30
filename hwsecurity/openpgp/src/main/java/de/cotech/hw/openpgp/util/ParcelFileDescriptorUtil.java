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


import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import android.content.Context;
import android.os.Build;
import android.os.ParcelFileDescriptor;


/**
 * Utility class for loading streamed data into a seekable {@link ParcelFileDescriptor}.
 *
 * <p>
 * This covers the use case of passing streaming data via an ACTION_SEND or similar Intent, without caching to a file.
 * This is especially useful for encrypted files, e.g. from a {@link DecryptingFileInputStream}.
 *
 * <p>
 * Unlike ParcelFileDescriptors obtained from a {@link ParcelFileDescriptor#createPipe()}, this method returns a
 * <i>seekable</i> ParcelFileDescriptor. In practice, virtually all receivers of Intents with streamed data require
 * seekable file descriptors. {@link android.content.ContentProvider}
 *
 * <p>
 * <pre>{@code
 * ParcelFileDescriptor openFile(Uri uri, String mode) {
 *     try {
 *         File file = database.getEncryptedFilenameForUri(uri);
 *         int plaintextLength = getPlaintextLengthForUri(uri);
 *         return parcelFileDescriptorCompat.loadToParcelFileDescriptor(file, plaintextLength);
 *     } catch (e: IOException) {
 *         throw new FileNotFoundException(e.getMessage());
 *     }
 * }
 * }</pre>
 * <p>
 * Internally, this uses one of two mechanisms:
 * <ul>
 *     <li>On Android O (sdk 26) or higher, it uses a {@link android.os.ProxyFileDescriptorCallback} backed by a
 *          reference-counted {@link android.os.MemoryFile}.</li>
 *     <li>On earlier Android versions, it falls back to a mechanism based on ephemeral file descriptors. To this end,
 *          it creates a file on storage that is deleted immediately after opening a couple of file descriptors. These
 *          file descriptors are cached and used for any subsequent access. Note that this method does <b>not</b> keep
 *          data strictly in-memory, but it's as close as we could get.</li>
 * </ul>
 * <p>
 * <b>Note:</b> in our tests, the technique of extracting the internal file descriptor of a MemoryFile using reflection
 * did <i>not</i> actually yield a seekable ParcelFileDescriptor that worked as intended.
 */
public class ParcelFileDescriptorUtil {
    private MemoryFilePfdUtil memoryFilePfdUtil;
    private EphemeralFilePfdUtil ephemeralFilePfdUtil;

    public ParcelFileDescriptorUtil(Context context) {
        this.memoryFilePfdUtil = new MemoryFilePfdUtil(context);
        this.ephemeralFilePfdUtil = new EphemeralFilePfdUtil(context);
    }

    /**
     * This method
     *
     * @param inputStreamProvider A closure that returns an InputStream with the desired file content.
     * @param cacheId An id that identifies the content, for caching purposes.
     */
    public ParcelFileDescriptor loadToParcelFileDescriptor(
            InputStreamProvider inputStreamProvider, String cacheId) throws IOException {
        return loadToParcelFileDescriptor(inputStreamProvider, cacheId, 0);
    }

    public ParcelFileDescriptor loadToParcelFileDescriptor(
            InputStreamProvider inputStreamProvider, String cacheId, int fileSize) throws IOException {
        // Unfortunately, a MemoryFile doesn't actually work as a seekable file descriptor. We tried.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && fileSize > 0) {
            return memoryFilePfdUtil.loadDataToFileDescriptorCallback(cacheId, fileSize, inputStreamProvider);
        } else {
            return ephemeralFilePfdUtil.loadDataToFileDescriptor(cacheId, inputStreamProvider);
        }
    }

    /**
     * Simple interface for obtaining an InputStream.
     *
     * @see #loadToParcelFileDescriptor
     */
    public interface InputStreamProvider {
        InputStream getInputStream() throws FileNotFoundException;
    }
}
