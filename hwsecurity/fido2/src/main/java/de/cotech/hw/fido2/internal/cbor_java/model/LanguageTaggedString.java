package de.cotech.hw.fido2.internal.cbor_java.model;

import java.util.Objects;

/**
 * See https://peteroupc.github.io/CBOR/langtags.html
 */
public class LanguageTaggedString extends Array {

    public LanguageTaggedString(String language, String string) {
        this(new UnicodeString(language), new UnicodeString(string));
    }

    public LanguageTaggedString(UnicodeString language, UnicodeString string) {
        setTag(38);
        add(Objects.requireNonNull(language));
        add(Objects.requireNonNull(string));
    }

    public UnicodeString getLanguage() {
        return (UnicodeString) getDataItems().get(0);
    }

    public UnicodeString getString() {
        return (UnicodeString) getDataItems().get(1);
    }

}
