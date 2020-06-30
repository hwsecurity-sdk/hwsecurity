package de.cotech.hw.fido2.internal.cbor_java;

import java.io.OutputStream;
import java.util.List;
import java.util.Objects;

import de.cotech.hw.fido2.internal.cbor_java.encoder.ArrayEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.ByteStringEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.MapEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.NegativeIntegerEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.SpecialEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.TagEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.UnicodeStringEncoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.UnsignedIntegerEncoder;
import de.cotech.hw.fido2.internal.cbor_java.model.Array;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.NegativeInteger;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;
import de.cotech.hw.fido2.internal.cbor_java.model.Special;
import de.cotech.hw.fido2.internal.cbor_java.model.Tag;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;

/**
 * Encoder for the CBOR format based.
 */
public class CborEncoder {

    private final UnsignedIntegerEncoder unsignedIntegerEncoder;
    private final NegativeIntegerEncoder negativeIntegerEncoder;
    private final ByteStringEncoder byteStringEncoder;
    private final UnicodeStringEncoder unicodeStringEncoder;
    private final ArrayEncoder arrayEncoder;
    private final MapEncoder mapEncoder;
    private final TagEncoder tagEncoder;
    private final SpecialEncoder specialEncoder;

    /**
     * Initialize a new encoder which writes the binary encoded data to an
     * {@link OutputStream}.
     */
    public CborEncoder(OutputStream outputStream) {
        Objects.requireNonNull(outputStream);
        unsignedIntegerEncoder = new UnsignedIntegerEncoder(this, outputStream);
        negativeIntegerEncoder = new NegativeIntegerEncoder(this, outputStream);
        byteStringEncoder = new ByteStringEncoder(this, outputStream);
        unicodeStringEncoder = new UnicodeStringEncoder(this, outputStream);
        arrayEncoder = new ArrayEncoder(this, outputStream);
        mapEncoder = new MapEncoder(this, outputStream);
        tagEncoder = new TagEncoder(this, outputStream);
        specialEncoder = new SpecialEncoder(this, outputStream);
    }

    /**
     * Encode a list of {@link DataItem}s, also known as a stream.
     *
     * @param dataItems
     *            a list of {@link DataItem}s
     * @throws CborException
     *             if the {@link DataItem}s could not be encoded or there was an
     *             problem with the {@link OutputStream}.
     */
    public void encode(List<DataItem> dataItems) throws CborException {
        for (DataItem dataItem : dataItems) {
            encode(dataItem);
        }
    }

    /**
     * Encode a single {@link DataItem}.
     *
     * @param dataItem
     *            the {@link DataItem} to encode. If null, encoder encodes a
     *            {@link SimpleValue} NULL value.
     * @throws CborException
     *             if {@link DataItem} could not be encoded or there was an
     *             problem with the {@link OutputStream}.
     */
    public void encode(DataItem dataItem) throws CborException {
        if (dataItem == null) {
            dataItem = SimpleValue.NULL;
        }

        if (dataItem.hasTag()) {
            Tag tagDi = dataItem.getTag();
            tagEncoder.encode(tagDi);
        }

        switch (dataItem.getMajorType()) {
        case UNSIGNED_INTEGER:
            unsignedIntegerEncoder.encode((UnsignedInteger) dataItem);
            break;
        case NEGATIVE_INTEGER:
            negativeIntegerEncoder.encode((NegativeInteger) dataItem);
            break;
        case BYTE_STRING:
            byteStringEncoder.encode((ByteString) dataItem);
            break;
        case UNICODE_STRING:
            unicodeStringEncoder.encode((UnicodeString) dataItem);
            break;
        case ARRAY:
            arrayEncoder.encode((Array) dataItem);
            break;
        case MAP:
            mapEncoder.encode((Map) dataItem);
            break;
        case SPECIAL:
            specialEncoder.encode((Special) dataItem);
            break;
        case TAG:
            tagEncoder.encode((Tag) dataItem);
            break;
        default:
            throw new CborException("Unknown major type");
        }
    }

}
