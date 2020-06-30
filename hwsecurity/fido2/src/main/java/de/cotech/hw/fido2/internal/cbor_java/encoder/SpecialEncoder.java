package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.DoublePrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.HalfPrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValueType;
import de.cotech.hw.fido2.internal.cbor_java.model.SinglePrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.Special;

public class SpecialEncoder extends AbstractEncoder<Special> {

    private final HalfPrecisionFloatEncoder halfPrecisionFloatEncoder;
    private final SinglePrecisionFloatEncoder singlePrecisionFloatEncoder;
    private final DoublePrecisionFloatEncoder doublePrecisionFloatEncoder;

    public SpecialEncoder(CborEncoder encoder, OutputStream outputStream) {
        super(encoder, outputStream);
        halfPrecisionFloatEncoder = new HalfPrecisionFloatEncoder(encoder, outputStream);
        singlePrecisionFloatEncoder = new SinglePrecisionFloatEncoder(encoder, outputStream);
        doublePrecisionFloatEncoder = new DoublePrecisionFloatEncoder(encoder, outputStream);
    }

    @Override
    public void encode(Special dataItem) throws CborException {
        switch (dataItem.getSpecialType()) {
        case BREAK:
            write((7 << 5) | 31);
            break;
        case SIMPLE_VALUE:
            SimpleValue simpleValue = (SimpleValue) dataItem;
            switch (simpleValue.getSimpleValueType()) {
            case FALSE:
            case NULL:
            case TRUE:
            case UNDEFINED:
                SimpleValueType type = simpleValue.getSimpleValueType();
                write((7 << 5) | type.getValue());
                break;
            case UNALLOCATED:
                write((7 << 5) | simpleValue.getValue());
                break;
            case RESERVED:
                break;
            }
            break;
        case UNALLOCATED:
            throw new CborException("Unallocated special type");
        case IEEE_754_HALF_PRECISION_FLOAT:
            if (!(dataItem instanceof HalfPrecisionFloat)) {
                throw new CborException("Wrong data item type");
            }
            halfPrecisionFloatEncoder.encode((HalfPrecisionFloat) dataItem);
            break;
        case IEEE_754_SINGLE_PRECISION_FLOAT:
            if (!(dataItem instanceof SinglePrecisionFloat)) {
                throw new CborException("Wrong data item type");
            }
            singlePrecisionFloatEncoder.encode((SinglePrecisionFloat) dataItem);
            break;
        case IEEE_754_DOUBLE_PRECISION_FLOAT:
            if (!(dataItem instanceof DoublePrecisionFloat)) {
                throw new CborException("Wrong data item type");
            }
            doublePrecisionFloatEncoder.encode((DoublePrecisionFloat) dataItem);
            break;
        case SIMPLE_VALUE_NEXT_BYTE:
            if (!(dataItem instanceof SimpleValue)) {
                throw new CborException("Wrong data item type");
            }
            SimpleValue simpleValueNextByte = (SimpleValue) dataItem;
            write((7 << 5) | 24);
            write(simpleValueNextByte.getValue());
            break;
        }
    }

}
