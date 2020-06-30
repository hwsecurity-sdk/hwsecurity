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
import java.io.OutputStream;
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
import javax.crypto.spec.SecretKeySpec;

/**
 * An {@link OutputStream} that encrypts data with a {@link ByteSecret}.
 *
 * <pre>{@code
 * ByteSecret secret = SecretGenerator.getInstance().createRandom(32);
 * EncryptingFileOutputStream efos = new EncryptingFileOutputStream(new File("filename.encrypted"), secret);
 * try {
 *     efos.write("hello!\n");
 * } finally {
 *     efos.close();
 * }
 * BufferedReader reader = new BufferedReader(new DecryptingFileOutputStream(new File("filename.encrypted"), secret));
 * try {
 *     String line = reader.readLine();
 *     assertEquals("hello!\n", line);
 * } finally {
 *     reader.close();
 * }
 * }</pre>
 * <p>
 *
 * Internally, this uses AES-GCM for authenticated encryption. The randomly generated nonce is stored as part of the file.
 *
 * @see DecryptingFileInputStream
 */
public class EncryptingFileOutputStream extends OutputStream {
    private final OutputStream outputStream;
    private final Cipher cipher;
    private boolean closed = false;

    public EncryptingFileOutputStream(@NonNull File file, ByteSecret byteSecret) throws IOException {
        super();

        outputStream = new BufferedOutputStream(new FileOutputStream(file));

        try {
            byte[] secretBytes = byteSecret.getByteCopyAndClear();
            SecretKeySpec secretKey = new SecretKeySpec(secretBytes, "AES");
            Arrays.fill(secretBytes, (byte) 0);

            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            if (iv.length > 255) {
                throw new AssertionError();
            }
            outputStream.write(new byte[] { (byte) iv.length }, 0, 1);
            outputStream.write(iv, 0, iv.length);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public void write(int i) throws IOException {
        write(new byte[] { (byte) i });
    }

    @Override
    public void write(@NonNull byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }

    @Override
    public void write(@NonNull byte[] buffer, int off, int len) throws IOException {
        byte[] buf = cipher.update(buffer, off, len);
        if (buf != null) {
            outputStream.write(buf);
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        try {
            byte[] bytes = cipher.doFinal();
            outputStream.write(bytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException(e);
        } finally {
            closed = true;
        }

        outputStream.close();
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }
}
