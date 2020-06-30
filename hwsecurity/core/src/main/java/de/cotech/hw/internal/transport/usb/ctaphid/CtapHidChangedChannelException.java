package de.cotech.hw.internal.transport.usb.ctaphid;


import de.cotech.hw.internal.transport.usb.UsbTransportException;


class CtapHidChangedChannelException extends UsbTransportException {
    CtapHidChangedChannelException(int expectedChannelId, int actualChannelId) {
        super("Channel changed during transaction, " + expectedChannelId + " to " + actualChannelId);
    }
}
