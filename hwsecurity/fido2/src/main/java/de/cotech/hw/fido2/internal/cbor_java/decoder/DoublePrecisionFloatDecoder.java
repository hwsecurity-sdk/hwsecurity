package de.cotech.hw.fido2.internal.cbor_java.decoder;

import java.io.InputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.DoublePrecisionFloat;

public class DoublePrecisionFloatDecoder extends
                AbstractDecoder<DoublePrecisionFloat> {

    public DoublePrecisionFloatDecoder(CborDecoder decoder,
                    InputStream inputStream) {
        super(decoder, inputStream);
    }

    @Override
    public DoublePrecisionFloat decode(int initialByte) throws CborException {
        long bits = 0;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        bits <<= 8;
        bits |= nextSymbol() & 0xFF;
        return new DoublePrecisionFloat(Double.longBitsToDouble(bits));
    }

}
