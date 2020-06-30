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


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import androidx.annotation.NonNull;

import de.cotech.hw.secrets.ByteSecret;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * An {@link InputStream} that decrypts data with a {@link ByteSecret}.
 *
 * See {@link DecryptingFileInputStream}.
 *
 * @see DecryptingFileInputStream
 */
public class DecryptingFileInputStream extends InputStream {
    private final Cipher cipher;

    private final InputStream inputStream;
    private final long totalCiphertextLength;
    private long totalCiphertextRead;

    private byte[] ciphertextBuf = new byte[2048];
    private byte[] cleartextBuf = new byte[2048];
    private int cleartextPosition;
    private int cleartextLength;

    public DecryptingFileInputStream(@NonNull File file, ByteSecret byteSecret) throws IOException {
        super();

        if (!file.exists()) {
            throw new FileNotFoundException();
        }

        inputStream = new BufferedInputStream(new FileInputStream(file));
        totalCiphertextLength = file.length();

        byte[] sessionKey = byteSecret.getByteCopyAndClear();
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            int ivLength = inputStream.read();
            byte[] iv = new byte[ivLength];
            int ivRead = inputStream.read(iv);
            if (ivRead != ivLength) {
                throw new AssertionError();
            }

            totalCiphertextRead += 1 + ivLength;
            SecretKeySpec secretKey = new SecretKeySpec(sessionKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        } finally {
            Arrays.fill(sessionKey, (byte) 0);
        }
    }

    @Override
    public int read() throws IOException {
        fillDecryptedBuffer();
        if (cleartextLength == -1) {
            return -1;
        }
        return cleartextBuf[cleartextPosition++];
    }

    @Override
    public int read(@NonNull byte[] buffer) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    @Override
    public int read(@NonNull byte[] buffer, int offset, int length) throws IOException {
        int totalBytesRead = 0;
        while (length > 0) {
            fillDecryptedBuffer();

            if (cleartextLength == -1) {
                return totalBytesRead > 0 ? totalBytesRead : -1;
            }

            int bytesToCopy = Math.min(length, cleartextAvailable());
            System.arraycopy(cleartextBuf, cleartextPosition, buffer, offset, bytesToCopy);
            cleartextPosition += bytesToCopy;
            length -= bytesToCopy;
            offset += bytesToCopy;
            totalBytesRead += bytesToCopy;
        }
        return totalBytesRead;
    }

    private void fillDecryptedBuffer() throws IOException {
        if (cleartextAvailable() > 0) {
            return;
        }
        if (totalCiphertextLength == totalCiphertextRead) {
            cleartextLength = -1;
            return;
        }
        int bytesRead = inputStream.read(ciphertextBuf, 0, ciphertextBuf.length);
        totalCiphertextRead += bytesRead;
        try {
            if (totalCiphertextRead < totalCiphertextLength) {
                cleartextLength = cipher.update(ciphertextBuf, 0, bytesRead, cleartextBuf);
            } else {
                cleartextLength = cipher.doFinal(ciphertextBuf, 0, bytesRead, cleartextBuf);
            }
            cleartextPosition = 0;
        } catch (BadPaddingException e) {
            throw new IOException(e);
        } catch (ShortBufferException | IllegalBlockSizeException e) {
            throw new AssertionError(e);
        }
    }

    private int cleartextAvailable() {
        return cleartextLength - cleartextPosition;
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
