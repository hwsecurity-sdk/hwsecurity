package de.cotech.hw.internal.transport.usb.u2fhid;


import de.cotech.hw.internal.transport.usb.UsbTransportException;


class U2fHidChangedChannelException extends UsbTransportException {
    U2fHidChangedChannelException(int expectedChannelId, int actualChannelId) {
        super("Channel changed during transaction, " + expectedChannelId + " to " + actualChannelId);
    }
}
