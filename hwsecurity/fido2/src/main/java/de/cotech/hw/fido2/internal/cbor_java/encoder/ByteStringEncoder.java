package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;

public class ByteStringEncoder extends AbstractEncoder<ByteString> {

    public ByteStringEncoder(CborEncoder encoder, OutputStream outputStream) {
        super(encoder, outputStream);
    }

    @Override
    public void encode(ByteString byteString) throws CborException {
        byte[] bytes = byteString.getBytes();
        if (byteString.isChunked()) {
            encodeTypeChunked(MajorType.BYTE_STRING);
            if (bytes != null) {
                encode(new ByteString(bytes));
            }
        } else if (bytes == null) {
            encoder.encode(SimpleValue.NULL);
        } else {
            encodeTypeAndLength(MajorType.BYTE_STRING, bytes.length);
            write(bytes);
        }
    }

}
