package de.cotech.hw.fido2.internal.cbor_java.builder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.decoder.HalfPrecisionFloatDecoder;
import de.cotech.hw.fido2.internal.cbor_java.encoder.HalfPrecisionFloatEncoder;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.DoublePrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.HalfPrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.NegativeInteger;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;
import de.cotech.hw.fido2.internal.cbor_java.model.SinglePrecisionFloat;
import de.cotech.hw.fido2.internal.cbor_java.model.Tag;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;

public abstract class AbstractBuilder<T> {

    private final T parent;

    public AbstractBuilder(T parent) {
        this.parent = parent;
    }

    protected T getParent() {
        return parent;
    }

    protected void addChunk(DataItem dataItem) {
        throw new IllegalStateException();
    }

    protected DataItem convert(long value) {
        if (value >= 0) {
            return new UnsignedInteger(value);
        } else {
            return new NegativeInteger(value);
        }
    }

    protected DataItem convert(BigInteger value) {
        if (value.signum() == -1) {
            return new NegativeInteger(value);
        } else {
            return new UnsignedInteger(value);
        }
    }

    protected DataItem convert(boolean value) {
        if (value) {
            return SimpleValue.TRUE;
        } else {
            return SimpleValue.FALSE;
        }
    }

    protected DataItem convert(byte[] bytes) {
        return new ByteString(bytes);
    }

    protected DataItem convert(String string) {
        return new UnicodeString(string);
    }

    protected DataItem convert(float value) {
        if (isHalfPrecisionEnough(value)) {
            return new HalfPrecisionFloat(value);
        } else {
            return new SinglePrecisionFloat(value);
        }
    }

    protected DataItem convert(double value) {
        return new DoublePrecisionFloat(value);
    }

    protected Tag tag(long value) {
        return new Tag(value);
    }

    private boolean isHalfPrecisionEnough(float value) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            HalfPrecisionFloatEncoder encoder = getHalfPrecisionFloatEncoder(outputStream);
            encoder.encode(new HalfPrecisionFloat(value));
            byte[] bytes = outputStream.toByteArray();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            HalfPrecisionFloatDecoder decoder = getHalfPrecisionFloatDecoder(inputStream);
            if (inputStream.read() == -1) { // to skip type byte
                throw new CborException("unexpected end of stream");
            }
            HalfPrecisionFloat halfPrecisionFloat = decoder.decode(0);
            return value == halfPrecisionFloat.getValue();
        } catch (CborException cborException) {
            return false;
        }
    }

    protected HalfPrecisionFloatEncoder getHalfPrecisionFloatEncoder(OutputStream outputStream) {
        return new HalfPrecisionFloatEncoder(null, outputStream);
    }

    protected HalfPrecisionFloatDecoder getHalfPrecisionFloatDecoder(InputStream inputStream) {
        return new HalfPrecisionFloatDecoder(null, inputStream);
    }

}
