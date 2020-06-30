package de.cotech.hw.fido2.internal.cbor_java.builder;

import de.cotech.hw.fido2.internal.cbor_java.model.Array;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.SimpleValue;

public class ArrayBuilder<T extends AbstractBuilder<?>> extends
                AbstractBuilder<T> {

    private final Array array;

    public ArrayBuilder(T parent, Array array) {
        super(parent);
        this.array = array;
    }

    public ArrayBuilder<T> add(DataItem dataItem) {
        array.add(dataItem);
        return this;
    }

    public ArrayBuilder<T> add(long value) {
        add(convert(value));
        return this;
    }

    public ArrayBuilder<T> add(boolean value) {
        add(convert(value));
        return this;
    }

    public ArrayBuilder<T> add(float value) {
        add(convert(value));
        return this;
    }

    public ArrayBuilder<T> add(double value) {
        add(convert(value));
        return this;
    }

    public ArrayBuilder<T> add(byte[] bytes) {
        add(convert(bytes));
        return this;
    }

    public ArrayBuilder<T> add(String string) {
        add(convert(string));
        return this;
    }

    public ArrayBuilder<ArrayBuilder<T>> addArray() {
        Array nestedArray = new Array();
        add(nestedArray);
        return new ArrayBuilder<ArrayBuilder<T>>(this, nestedArray);
    }

    public ArrayBuilder<ArrayBuilder<T>> startArray() {
        Array nestedArray = new Array();
        nestedArray.setChunked(true);
        add(nestedArray);
        return new ArrayBuilder<ArrayBuilder<T>>(this, nestedArray);
    }

    public MapBuilder<ArrayBuilder<T>> addMap() {
        Map nestedMap = new Map();
        add(nestedMap);
        return new MapBuilder<ArrayBuilder<T>>(this, nestedMap);
    }

    public MapBuilder<ArrayBuilder<T>> startMap() {
        Map nestedMap = new Map();
        nestedMap.setChunked(true);
        add(nestedMap);
        return new MapBuilder<ArrayBuilder<T>>(this, nestedMap);
    }

    public T end() {
        if (array.isChunked()) {
            add(SimpleValue.BREAK);
        }
        return getParent();
    }

}
