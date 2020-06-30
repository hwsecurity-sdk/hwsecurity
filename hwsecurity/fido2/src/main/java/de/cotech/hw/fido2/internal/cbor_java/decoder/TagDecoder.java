package de.cotech.hw.fido2.internal.cbor_java.decoder;

import java.io.InputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.Tag;

public class TagDecoder extends AbstractDecoder<Tag> {

    public TagDecoder(CborDecoder decoder, InputStream inputStream) {
        super(decoder, inputStream);
    }

    @Override
    public Tag decode(int initialByte) throws CborException {
        return new Tag(getLength(initialByte));
    }

}
