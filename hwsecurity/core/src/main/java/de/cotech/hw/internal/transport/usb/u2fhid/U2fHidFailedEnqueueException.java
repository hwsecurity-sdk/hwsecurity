package de.cotech.hw.internal.transport.usb.u2fhid;


import de.cotech.hw.internal.transport.usb.UsbTransportException;


class U2fHidFailedEnqueueException extends UsbTransportException {
    U2fHidFailedEnqueueException(String message) {
        super(message);
    }
}
