package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.SinglePrecisionFloat;

public class SinglePrecisionFloatEncoder extends AbstractEncoder<SinglePrecisionFloat> {

	public SinglePrecisionFloatEncoder(CborEncoder encoder, OutputStream outputStream) {
		super(encoder, outputStream);
	}

	@Override
	public void encode(SinglePrecisionFloat dataItem) throws CborException {
		write((7 << 5) | 26);
		int bits = Float.floatToRawIntBits(dataItem.getValue());
		write((bits >> 24) & 0xFF);
		write((bits >> 16) & 0xFF);
		write((bits >> 8) & 0xFF);
		write((bits >> 0) & 0xFF);
	}

}
