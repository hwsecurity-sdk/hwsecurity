package de.cotech.hw.fido2.internal.cbor_java.decoder;

import java.io.InputStream;
import java.math.BigInteger;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.NegativeInteger;

public class NegativeIntegerDecoder extends AbstractDecoder<NegativeInteger> {

	private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

	public NegativeIntegerDecoder(CborDecoder decoder, InputStream inputStream) {
		super(decoder, inputStream);
	}

	@Override
	public NegativeInteger decode(int initialByte) throws CborException {
		return new NegativeInteger(MINUS_ONE.subtract(getLengthAsBigInteger(initialByte)));
	}

}
