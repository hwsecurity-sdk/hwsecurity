package de.cotech.hw.fido2.internal.cbor_java.builder;

import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;

public class UnicodeStringBuilder<T extends AbstractBuilder<?>> extends
                AbstractBuilder<T> {

    public UnicodeStringBuilder(T parent) {
        super(parent);
    }

    public UnicodeStringBuilder<T> add(String string) {
        getParent().addChunk(convert(string));
        return this;
    }

    public T end() {
        getParent().addChunk(SimpleValue.BREAK);
        return getParent();
    }

}
