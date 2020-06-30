package de.cotech.hw.fido2.internal.cbor_java.model;

public class SinglePrecisionFloat extends AbstractFloat {

    public SinglePrecisionFloat(float value) {
        super(SpecialType.IEEE_754_SINGLE_PRECISION_FLOAT, value);
    }

}
