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

package de.cotech.hw.internal.transport.nfc;


import java.io.IOException;

import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.os.SystemClock;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.internal.iso7816.CommandApdu;
import de.cotech.hw.internal.iso7816.ResponseApdu;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.SecurityKeyInfo.TransportType;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.util.HwTimber;

@RestrictTo(Scope.LIBRARY_GROUP)
public class NfcTransport implements Transport {
    private static final int CLA_MASK_CHAINING = 1 << 4;
    private static final int APDU_SW1_RESPONSE_AVAILABLE = 0x61;

    private static final int TIMEOUT = 5000;
    private static final int TIMEOUT_WHILE_CHAINING = 5000;
    // This is a GET DATA command, which should return a benign error
    private static final CommandApdu PING_APDU = CommandApdu.create(0x00, 0xc0, 0x00, 0x00);

    private final Tag mTag;
    private final boolean enableDebugLogging;
    private final boolean isPersistentlyManaged;
    private IsoDep mIsoDep;

    private final Object connectionLock = new Object();
    private volatile boolean isTransceiving = false;
    private volatile boolean isTransceivingChain = false;
    private volatile long lastTransceiveTime;

    private boolean released = false;
    private TransportReleasedCallback transportReleasedCallback;

    static NfcTransport createNfcTransport(Tag tag, boolean enableDebugLogging, boolean isPersistentlyManaged) {
        return new NfcTransport(tag, enableDebugLogging, isPersistentlyManaged);
    }

    private NfcTransport(Tag tag, boolean enableDebugLogging, boolean isPersistentlyManaged) {
        this.mTag = tag;
        this.enableDebugLogging = enableDebugLogging;
        this.isPersistentlyManaged = isPersistentlyManaged;
        this.lastTransceiveTime = System.currentTimeMillis();
    }

    @Override
    public ResponseApdu transceive(final CommandApdu commandApdu) throws IOException {
        if (!isConnected()) {
            throw new SecurityKeyDisconnectedException();
        }
        synchronized (connectionLock) {
            try {
                isTransceiving = true;
                isTransceivingChain = (commandApdu.getCLA() & CLA_MASK_CHAINING) == CLA_MASK_CHAINING;
                byte[] rawCommand = commandApdu.toBytes();
                if (enableDebugLogging) {
                    HwTimber.d("NFC out: %s", commandApdu);
                }

                long startRealtime = SystemClock.elapsedRealtime();
                byte[] rawResponse = mIsoDep.transceive(rawCommand);

                ResponseApdu responseApdu = ResponseApdu.fromBytes(rawResponse);
                if (enableDebugLogging) {
                    long totalTime = SystemClock.elapsedRealtime() - startRealtime;
                    HwTimber.d("NFC  in: %s", responseApdu);
                    HwTimber.d("NFC communication took %dms", totalTime);
                }

                if (responseApdu.getSw1() == APDU_SW1_RESPONSE_AVAILABLE) {
                    isTransceivingChain = true;
                }
                return responseApdu;
            } catch (TagLostException e) {
                throw new SecurityKeyDisconnectedException();
            } finally {
                lastTransceiveTime = System.currentTimeMillis();
                isTransceiving = false;
            }
        }
    }

    @Override
    public boolean ping() {
        if (!isConnected()) {
            return false;
        }
        HwTimber.d("Sending nfc ping…");
        long startTime = SystemClock.elapsedRealtime();
        try {
            transceive(PING_APDU);
            long totalTime = SystemClock.elapsedRealtime() - startTime;
            HwTimber.d("got pong in %dms!", totalTime);
            return true;
        } catch (TagLostException e) {
            long totalTime = SystemClock.elapsedRealtime() - startTime;
            HwTimber.d("tag lost, waited %dms!", totalTime);
            return false;
        } catch (IOException e) {
            long totalTime = SystemClock.elapsedRealtime() - startTime;
            HwTimber.e(e, "tag lost, waited %dms!", totalTime);
            return false;
        }
    }

    long getLastTransceiveTime() {
        if (isTransceiving) {
            return System.currentTimeMillis();
        }
        if (isTransceivingChain) {
            boolean isChainTransceiveTimeout = lastTransceiveTime + TIMEOUT_WHILE_CHAINING > System.currentTimeMillis();
            if (!isChainTransceiveTimeout) {
                HwTimber.d("Timeout while chaining commands!");
                return System.currentTimeMillis();
            }
        }
        return lastTransceiveTime;
    }

    @Override
    public void setTransportReleaseCallback(TransportReleasedCallback callback) {
        this.transportReleasedCallback = callback;
    }

    @Override
    public boolean isExtendedLengthSupported() {
        if (VERSION.SDK_INT >= VERSION_CODES.JELLY_BEAN) {
            return mIsoDep.isExtendedLengthApduSupported();
        } else {
            return false;
        }
    }

    @Override
    @WorkerThread
    public void release() {
        if (!released) {
            HwTimber.d("Nfc transport disconnected");
            this.released = true;
            if (transportReleasedCallback != null) {
                transportReleasedCallback.onTransportReleased();
            }
        }
    }

    @Override
    public boolean isConnected() {
        return mIsoDep != null && mIsoDep.isConnected();
    }

    @Override
    public boolean isReleased() {
        return released;
    }

    @Override
    public boolean isPersistentConnectionAllowed() {
        return isPersistentlyManaged;
    }

    /**
     * Connect to NFC device.
     * <p/>
     * On general communication, see also
     * http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_annex-a.aspx
     * <p/>
     * References to pages are generally related to the OpenPGP Application
     * on ISO SmartCard Systems specification.
     */
    @Override
    public void connect() throws IOException {
        mIsoDep = IsoDep.get(mTag);
        if (mIsoDep == null) {
            throw new IsoDepNotSupportedException("Tag does not support ISO-DEP (ISO 14443-4)");
        }

        mIsoDep.setTimeout(TIMEOUT);
        mIsoDep.connect();
    }

    @Override
    public TransportType getTransportType() {
        return TransportType.NFC;
    }

    @Nullable
    @Override
    public SecurityKeyInfo.SecurityKeyType getSecurityKeyTypeIfAvailable() {
        // Sadly, the NFC transport has no direct information about the security key type.
        return null;
    }

    public Tag getTag() {
        return mTag;
    }

    public static class IsoDepNotSupportedException extends IOException {
        IsoDepNotSupportedException(String detailMessage) {
            super(detailMessage);
        }
    }
}
