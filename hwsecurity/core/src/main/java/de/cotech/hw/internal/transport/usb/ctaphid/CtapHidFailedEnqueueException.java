package de.cotech.hw.internal.transport.usb.ctaphid;


import de.cotech.hw.internal.transport.usb.UsbTransportException;


class CtapHidFailedEnqueueException extends UsbTransportException {
    CtapHidFailedEnqueueException(String message) {
        super(message);
    }
}
