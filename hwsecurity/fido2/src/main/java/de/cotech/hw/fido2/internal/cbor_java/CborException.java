package de.cotech.hw.fido2.internal.cbor_java;

public class CborException extends Exception {

	private static final long serialVersionUID = 8839905301881841410L;

	public CborException(String message) {
		super(message);
	}

	public CborException(Throwable cause) {
		super(cause);
	}

	public CborException(String message, Throwable cause) {
		super(message, cause);
	}

}
