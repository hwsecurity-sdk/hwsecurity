package de.cotech.hw.fido2.internal.cbor_java.decoder;

import java.io.InputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.SinglePrecisionFloat;

public class SinglePrecisionFloatDecoder extends AbstractDecoder<SinglePrecisionFloat> {

	public SinglePrecisionFloatDecoder(CborDecoder decoder, InputStream inputStream) {
		super(decoder, inputStream);
	}

	@Override
	public SinglePrecisionFloat decode(int initialByte) throws CborException {
		int bits = 0;
		bits |= nextSymbol() & 0xFF;
		bits <<= 8;
		bits |= nextSymbol() & 0xFF;
		bits <<= 8;
		bits |= nextSymbol() & 0xFF;
		bits <<= 8;
		bits |= nextSymbol() & 0xFF;
		return new SinglePrecisionFloat(Float.intBitsToFloat(bits));
	}

}
