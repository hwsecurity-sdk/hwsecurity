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

package de.cotech.hw.internal.transport.usb.ctaphid;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbRequest;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;
import androidx.annotation.WorkerThread;
import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.internal.transport.usb.ctaphid.CtapHidFrameFactory.KeepaliveType;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
public class CtapHidTransportProtocol {
    @NonNull
    private final CtapHidInitStructFactory initStructFactory = new CtapHidInitStructFactory(new SecureRandom());
    @NonNull
    private final CtapHidFrameFactory frameFactory = new CtapHidFrameFactory();
    @NonNull
    private final UsbDeviceConnection usbCconnection;
    @NonNull
    private final UsbEndpoint usbEndpointIn;
    @NonNull
    private final UsbEndpoint usbEndpointOut;
    @NonNull
    private final ByteBuffer transferBuffer;
    @NonNull
    private final ExecutorService executor;

    private int channelId = CtapHidFrameFactory.CTAPHID_CHANNEL_ID_BROADCAST;

    CtapHidTransportProtocol(@NonNull UsbDeviceConnection usbCconnection,
                             @NonNull UsbEndpoint usbEndpointIn, @NonNull UsbEndpoint usbEndpointOut) {
        // noinspection ConstantConditions, checking method contract
        if (usbCconnection == null) {
            throw new NullPointerException();
        }
        // noinspection ConstantConditions, checking method contract
        if (usbEndpointIn == null) {
            throw new NullPointerException();
        }
        // noinspection ConstantConditions, checking method contract
        if (usbEndpointOut == null) {
            throw new NullPointerException();
        }

        this.usbCconnection = usbCconnection;
        this.usbEndpointIn = usbEndpointIn;
        this.usbEndpointOut = usbEndpointOut;
        // Allocating a direct buffer here *will break* on some android devices!
        this.transferBuffer = ByteBuffer.allocate(CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);
        this.executor = Executors.newSingleThreadExecutor();
    }

    @WorkerThread
    public void connect() throws UsbTransportException {
        HwTimber.d("Initializing CTAPHID transport…");

        this.channelId = negotiateChannelId();
    }

    private int negotiateChannelId() throws UsbTransportException {
        byte[] initRequestBytes = initStructFactory.createInitRequest();
        byte[] requestFrame = frameFactory.wrapFrame(channelId, CtapHidFrameFactory.CTAPHID_INIT, initRequestBytes);
        writeHidPacketsToUsbDevice(requestFrame);

        return performUsbRequestWithTimeout((thread, usbRequest) -> {
            checkInterrupt(thread);
            if (!usbRequest.initialize(usbCconnection, usbEndpointIn)) {
                throw new IOException("Read request could not be opened!");
            }

            while (true) {
                checkInterrupt(thread);
                transferBuffer.clear();
                if (!usbRequest.queue(transferBuffer, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE)) {
                    throw new CtapHidFailedEnqueueException("Failed to receive data!");
                }
                usbCconnection.requestWait();
                try {
                    byte[] response = frameFactory.unwrapFrame(channelId, CtapHidFrameFactory.CTAPHID_INIT, transferBuffer.array());
                    CtapHidInitStructFactory.CtapHidInitResponse initResponse = initStructFactory.parseInitResponse(response, initRequestBytes);

                    HwTimber.d("CTAPHID_INIT response: %s", initResponse);
                    return initResponse.channelId();
                } catch (UsbTransportException e) {
                    HwTimber.d("Ignoring unrelated INIT response");
                }
            }
        }, 850);
    }

    @WorkerThread
    byte[] transceive(byte[] payload) throws UsbTransportException {
        byte[] requestFrame = frameFactory.wrapFrame(channelId, CtapHidFrameFactory.CTAPHID_MSG, payload);
        writeHidPacketsToUsbDevice(requestFrame);

        byte[] responseFrame = readHidPacketsFromUsbDevice();
        return frameFactory.unwrapFrame(channelId, CtapHidFrameFactory.CTAPHID_MSG, responseFrame);
    }

    @WorkerThread
    byte[] transceiveCbor(byte[] payload) throws UsbTransportException {
        byte[] requestFrame = frameFactory.wrapFrame(channelId, CtapHidFrameFactory.CTAPHID_CBOR, payload);
        writeHidPacketsToUsbDevice(requestFrame);

        while (true) {
            byte[] responseFrame = readHidPacketsFromUsbDevice();
            KeepaliveType keepalivePacketType = frameFactory.unwrapFrameAsKeepalivePacket(responseFrame);
            if (keepalivePacketType != null) {
                HwTimber.d("Received keepalive packet (%s), waiting for response..", keepalivePacketType);
                continue;
            }
            return frameFactory.unwrapFrame(channelId, CtapHidFrameFactory.CTAPHID_CBOR, responseFrame);
        }
    }

    @WorkerThread
    private byte[] readHidPacketsFromUsbDevice() throws UsbTransportException {
        return performUsbRequestWithTimeout((thread, usbRequest) -> {
            checkInterrupt(thread);

            if (!usbRequest.initialize(usbCconnection, usbEndpointIn)) {
                throw new IOException("Read request could not be opened!");
            }

            checkInterrupt(thread);
            int expectedFrames = readUntilInitHeaderForChannel(usbRequest);

            byte[] data = new byte[expectedFrames * CtapHidFrameFactory.CTAPHID_BUFFER_SIZE];
            transferBuffer.clear();
            transferBuffer.get(data, 0, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);

            int offset = CtapHidFrameFactory.CTAPHID_BUFFER_SIZE;
            for (int i = 1; i < expectedFrames; i++) {
                checkInterrupt(thread);
                if (!usbRequest.queue(transferBuffer, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE)) {
                    throw new CtapHidFailedEnqueueException("Failed to receive data!");
                }
                usbCconnection.requestWait();
                transferBuffer.clear();
                transferBuffer.get(data, offset, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);
                offset += CtapHidFrameFactory.CTAPHID_BUFFER_SIZE;
            }

            return data;
        }, 2 * 1000);
    }

    private int readUntilInitHeaderForChannel(UsbRequest usbRequest) throws IOException {
        while (true) {
            if (!usbRequest.queue(transferBuffer, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE)) {
                throw new CtapHidFailedEnqueueException("Failed to receive data!");
            }
            usbCconnection.requestWait();

            transferBuffer.clear();
            try {
                return frameFactory.findExpectedFramesFromInitPacketHeader(channelId, transferBuffer);
            } catch (CtapHidChangedChannelException e) {
                HwTimber.d("Received message from wrong channel - ignoring");
            }
        }
    }

    @WorkerThread
    private void writeHidPacketsToUsbDevice(byte[] hidFrame) throws UsbTransportException {
        if ((hidFrame.length % CtapHidFrameFactory.CTAPHID_BUFFER_SIZE) != 0) {
            throw new IllegalArgumentException("Invalid HID frame size!");
        }

        performUsbRequestWithTimeout((thread, usbRequest) -> {
            checkInterrupt(thread);

            if (!usbRequest.initialize(usbCconnection, usbEndpointOut)) {
                throw new IOException("Request could not be opened!");
            }

            int offset = 0;
            while (offset < hidFrame.length) {
                checkInterrupt(thread);
                transferBuffer.clear();
                transferBuffer.put(hidFrame, offset, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE);
                if (!usbRequest.queue(transferBuffer, CtapHidFrameFactory.CTAPHID_BUFFER_SIZE)) {
                    throw new CtapHidFailedEnqueueException("Failed to send data!");
                }
                usbCconnection.requestWait(); // blocking
                offset += CtapHidFrameFactory.CTAPHID_BUFFER_SIZE;
            }

            return null;
        }, 1000);
    }

    @WorkerThread
    private <T> T performUsbRequestWithTimeout(UsbRequestTask<T> task, int timeoutMs) throws UsbTransportException {
        UsbRequest usbRequest = newUsbRequest();

        Future<T> future = executor.submit(() -> {
            Thread thread = Thread.currentThread();
            try {
                return task.performUsbRequest(thread, usbRequest);
            } finally {
                usbRequest.close();
            }
        });

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (ExecutionException e) {
            throw new UsbTransportException("Error transmitting data!", e.getCause());
        } catch (InterruptedException e) {
            future.cancel(true);
            throw new UsbTransportException("Received interrupt during usb transaction", e);
        } catch (TimeoutException e) {
            throw new UsbTransportException("Timed out transmitting data");
        }
    }

    @VisibleForTesting
    UsbRequest newUsbRequest() {
        return new UsbRequest();
    }

    @VisibleForTesting
    int getChannelId() {
        return channelId;
    }

    interface UsbRequestTask<T> {
        @WorkerThread
        T performUsbRequest(Thread thread, UsbRequest request) throws IOException, InterruptedException;
    }

    private static void checkInterrupt(Thread thread) throws InterruptedException {
        if (thread.isInterrupted()) {
            HwTimber.d("Received interrupt, canceling USB operation");
            throw new InterruptedException();
        }
    }
}
