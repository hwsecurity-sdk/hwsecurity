package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;
import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.Array;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;

public class ArrayEncoder extends AbstractEncoder<Array> {

    public ArrayEncoder(CborEncoder encoder, OutputStream outputStream) {
        super(encoder, outputStream);
    }

    @Override
    public void encode(Array array) throws CborException {
        List<DataItem> dataItems = array.getDataItems();
        if (array.isChunked()) {
            encodeTypeChunked(MajorType.ARRAY);
        } else {
            encodeTypeAndLength(MajorType.ARRAY, dataItems.size());
        }
        for (DataItem dataItem : dataItems) {
            encoder.encode(dataItem);
        }
    }

}
