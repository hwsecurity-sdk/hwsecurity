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

package de.cotech.hw.secrets;


import android.text.Editable;
import android.widget.TextView;
import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;


/**
 * A more secure wrapper for ByteBuffer.
 * <p>
 * This class wraps a ByteBuffer, and attempts to ensure that its memory is overwritten when the object is freed, to
 * keep secrets in memory as short a time as possible.
 */
public class ByteSecret {
    private ByteBuffer secret;

    @NonNull
    public static ByteSecret fromEditableAsUtf8AndClear(Editable editable) {
        /* EditText is not using String internally but char[].
        Thus, we can get the char[] directly from it. */
        int editableLength = editable.length();
        char[] chars = new char[editableLength];
        editable.getChars(0, editableLength, chars, 0);
        editable.clear();

        ByteBuffer secretCopy = fromCharArrayToByteBufferAsUtf8(chars);
        Arrays.fill(chars, '\u0000');

        return new ByteSecret(secretCopy);
    }

    @NonNull
    public static ByteSecret fromCharArrayAsUtf8TakeOwnership(char[] chars) {
        if (chars == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        ByteBuffer secretCopy = fromCharArrayToByteBufferAsUtf8(chars);
        Arrays.fill(chars, '\u0000');
        return new ByteSecret(secretCopy);
    }

    /**
     * Internal helper method to take a char array and encode it using UTF-8 in a ByteBuffer.
     */
    private static ByteBuffer fromCharArrayToByteBufferAsUtf8(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer encodedBuffer = Charset.forName("UTF-8").encode(charBuffer);
        // get only the actual used length
        ByteBuffer secretCopy = ByteBuffer.allocateDirect(chars.length);
        secretCopy.put(encodedBuffer);

        return secretCopy;
    }

    @NonNull
    public static ByteSecret fromByteArrayTakeOwnership(byte[] secret) {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return new ByteSecret(ByteBuffer.wrap(secret));
    }

    @NonNull
    public static ByteSecret fromByteArrayAndClear(byte[] secret) {
        return fromByteArrayAndClear(secret, secret.length);
    }

    @NonNull
    public static ByteSecret fromByteArrayAndClear(byte[] secret, int length) {
        ByteBuffer secretCopy = ByteBuffer.allocateDirect(length);
        secretCopy.put(secret, 0, length);
        Arrays.fill(secret, (byte) 0);
        return new ByteSecret(secretCopy);
    }

    @NonNull
    public static ByteSecret unsafeFromString(String secret) {
        ByteBuffer secretCopy = ByteBuffer.allocateDirect(secret.length());
        secretCopy.put(secret.getBytes());
        return new ByteSecret(secretCopy);
    }

    @NonNull
    public static ByteSecret moveFromByteSecret(ByteSecret byteSecret) {
        try {
            return new ByteSecret(byteSecret.secret);
        } finally {
            byteSecret.secret = null;
        }
    }

    private ByteSecret(ByteBuffer secret) {
        this.secret = secret;
        secret.clear();
    }

    public void displayOnTextView(TextView textView) {
        CharBuffer charBuffer = Charset.forName("UTF-8").decode(secret);
        textView.setText(charBuffer.array(), 0, charBuffer.length());
    }

    public byte[] unsafeGetByteCopy() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        byte[] copy = new byte[secret.capacity()];
        secret.get(copy);
        secret.clear();
        return copy;
    }

    public byte[] getByteCopyAndClear() {
        try {
            return unsafeGetByteCopy();
        } finally {
            removeFromMemory();
        }
    }

    public boolean isEmpty() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return (length() == 0);
    }

    public int length() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return secret.capacity();
    }

    public void removeFromMemory() {
        if (secret == null) {
            return;
        }
        secret.clear();
        while (secret.hasRemaining()) {
            secret.put((byte) 0);
        }
        secret = null;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ByteSecret) {
            ByteSecret other = (ByteSecret) obj;
            if (isEmpty() != other.isEmpty()) {
                return false;
            }
            return compareConstantTime(secret, other.secret);
        }
        return false;
    }

    private boolean compareConstantTime(ByteBuffer a, ByteBuffer b) {
        if (a.limit() != b.limit()) {
            return false;
        }
        if (a.position() != b.position()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.limit(); i++) {
            result |= a.get(i) ^ b.get(i);
        }
        return result == 0;
    }

    @Override
    public void finalize() throws Throwable {
        removeFromMemory();
        super.finalize();
    }

    public ByteSecret copy() {
        return ByteSecret.fromByteArrayTakeOwnership(unsafeGetByteCopy());
    }
}
