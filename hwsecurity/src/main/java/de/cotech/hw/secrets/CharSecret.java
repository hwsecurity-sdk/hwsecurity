/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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


import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Arrays;

import androidx.annotation.NonNull;
import android.text.Editable;


/**
 * A more secure wrapper for CharBuffer.
 * <p>
 * This class wraps a CharBuffer, and attempts to ensure that its memory is overwritten when the object is freed, to
 * keep secrets in memory as short a time as possible.
 *
 * @see ByteSecret
 * @deprecated Please use ByteSecret
 */
@Deprecated
public class CharSecret {
    private CharBuffer secret;

    @Deprecated
    @NonNull
    public static CharSecret fromEditableAndClear(Editable editable) {
        /* According to http://stackoverflow.com/a/15844273 EditText is not using String internally
         * but char[]. Thus, we can get the char[] directly from it. */
        int pl = editable.length();
        char[] chars = new char[pl];
        editable.getChars(0, pl, chars, 0);

        CharBuffer secretCopy = ByteBuffer.allocateDirect(chars.length * 2).asCharBuffer();
        secretCopy.put(chars);
        Arrays.fill(chars, '\u0000');

        return new CharSecret(secretCopy);
    }

    @Deprecated
    @NonNull
    public static CharSecret fromCharArrayTakeOwnership(char[] secret) {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return new CharSecret(CharBuffer.wrap(secret));
    }

    @Deprecated
    @NonNull
    public static CharSecret fromCharArrayAndClear(char[] secret) {
        CharBuffer secretCopy = ByteBuffer.allocateDirect(secret.length * 2).asCharBuffer();
        secretCopy.put(secret);
        Arrays.fill(secret, '\0');
        return new CharSecret(secretCopy);
    }

    @Deprecated
    @NonNull
    public static CharSecret unsafeFromString(String secret) {
        CharBuffer secretCopy = CharBuffer.allocate(secret.length());
        secretCopy.put(secret.toCharArray());
        return new CharSecret(secretCopy);
    }

    @Deprecated
    @NonNull
    public static CharSecret moveFromCharSecret(CharSecret charSecret) {
        try {
            return new CharSecret(charSecret.secret);
        } finally {
            charSecret.secret = null;
        }
    }

    @Deprecated
    private CharSecret(CharBuffer secret) {
        this.secret = secret;
        secret.clear();
    }

    @Deprecated
    public char[] unsafeGetCharCopy() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        char[] result = new char[secret.capacity()];
        for (int i = 0; i < result.length; i++) {
            result[i] = (char) secret.get(i);
        }
        return result;
    }

    @Deprecated
    public char[] getCharCopyAndClear() {
        try {
            return unsafeGetCharCopy();
        } finally {
            removeFromMemory();
        }
    }

    @Deprecated
    public boolean isEmpty() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return (length() == 0);
    }

    @Deprecated
    public int length() {
        if (secret == null) {
            throw new IllegalStateException("Secret has been cleared up before this call!");
        }
        return secret.capacity();
    }

    @Deprecated
    public void removeFromMemory() {
        if (secret == null) {
            return;
        }
        secret.clear();
        while (secret.hasRemaining()) {
            secret.put('\0');
        }
        secret = null;
    }

    @Deprecated
    @Override
    public void finalize() throws Throwable {
        removeFromMemory();
        super.finalize();
    }

    @Deprecated
    public CharSecret copy() {
        return CharSecret.fromCharArrayTakeOwnership(unsafeGetCharCopy());
    }
}
