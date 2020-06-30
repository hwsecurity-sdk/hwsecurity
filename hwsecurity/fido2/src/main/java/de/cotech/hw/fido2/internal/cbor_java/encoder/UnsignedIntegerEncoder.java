package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;

public class UnsignedIntegerEncoder extends AbstractEncoder<UnsignedInteger> {

    public UnsignedIntegerEncoder(CborEncoder encoder, OutputStream outputStream) {
        super(encoder, outputStream);
    }

    @Override
    public void encode(UnsignedInteger dataItem) throws CborException {
        encodeTypeAndLength(MajorType.UNSIGNED_INTEGER, dataItem.getValue());
    }

}
