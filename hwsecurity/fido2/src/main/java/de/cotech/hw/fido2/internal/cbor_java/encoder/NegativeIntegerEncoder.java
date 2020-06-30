package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;
import java.math.BigInteger;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.NegativeInteger;

public class NegativeIntegerEncoder extends AbstractEncoder<NegativeInteger> {

	private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);

	public NegativeIntegerEncoder(CborEncoder encoder, OutputStream outputStream) {
		super(encoder, outputStream);
	}

	@Override
	public void encode(NegativeInteger dataItem) throws CborException {
		encodeTypeAndLength(MajorType.NEGATIVE_INTEGER, MINUS_ONE.subtract(dataItem.getValue()).abs());
	}

}
