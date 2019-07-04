package de.cotech.hw.exceptions;


import java.io.IOException;


public class TransportGoneException extends IOException {
    public TransportGoneException(Throwable cause) {
        super("Transport is gone", cause);
    }

    public TransportGoneException() {
        this(null);
    }
}
