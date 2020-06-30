package de.cotech.hw.fido2.internal.cbor_java.model;

import java.math.BigInteger;

public class UnsignedInteger extends Number {

	public UnsignedInteger(long value) {
		this(BigInteger.valueOf(value));
		assertTrue(value >= 0L, "value " + value + " is not >= 0");
	}

	public UnsignedInteger(BigInteger value) {
		super(MajorType.UNSIGNED_INTEGER, value);
	}

}
