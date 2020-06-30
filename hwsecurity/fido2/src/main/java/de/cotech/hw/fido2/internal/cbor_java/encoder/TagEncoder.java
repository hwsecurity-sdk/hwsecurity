package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.Tag;

public class TagEncoder extends AbstractEncoder<Tag> {

    public TagEncoder(CborEncoder encoder, OutputStream outputStream) {
        super(encoder, outputStream);
    }

    @Override
    public void encode(Tag tag) throws CborException {
        encodeTypeAndLength(MajorType.TAG, tag.getValue());
    }

}
