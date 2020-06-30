package de.cotech.hw.fido2.internal.cbor_java.decoder;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.Special;

public class ByteStringDecoder extends AbstractDecoder<ByteString> {

    public ByteStringDecoder(CborDecoder decoder, InputStream inputStream) {
        super(decoder, inputStream);
    }

    @Override
    public ByteString decode(int initialByte) throws CborException {
        long length = getLength(initialByte);
        if (length == INFINITY) {
            if (decoder.isAutoDecodeInfinitiveByteStrings()) {
                return decodeInfinitiveLength();
            } else {
                ByteString byteString = new ByteString(null);
                byteString.setChunked(true);
                return byteString;
            }
        } else {
            return decodeFixedLength(length);
        }
    }

    private ByteString decodeInfinitiveLength() throws CborException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (;;) {
            DataItem dataItem = decoder.decodeNext();
            if (dataItem == null) {
                throw new CborException("Unexpected end of stream");
            }
            MajorType majorType = dataItem.getMajorType();
            if (Special.BREAK.equals(dataItem)) {
                break;
            } else if (majorType == MajorType.BYTE_STRING) {
                ByteString byteString = (ByteString) dataItem;
                byte[] byteArray = byteString.getBytes();
                if (byteArray != null) {
                    bytes.write(byteArray, 0, byteArray.length);
                }
            } else {
                throw new CborException("Unexpected major type "
                        + majorType);
            }
        }
        return new ByteString(bytes.toByteArray());
    }

    private ByteString decodeFixedLength(long length) throws CborException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) length);
        for (long i = 0; i < length; i++) {
            bytes.write(nextSymbol());
        }
        return new ByteString(bytes.toByteArray());
    }

}
