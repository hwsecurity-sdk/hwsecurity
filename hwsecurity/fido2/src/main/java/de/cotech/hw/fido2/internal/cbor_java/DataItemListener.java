package de.cotech.hw.fido2.internal.cbor_java;

import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;

/**
 * Callback interface for a streaming {@link CborDecoder}.
 */
public interface DataItemListener {

	/**
	 * Gets called on every decoded {@link DataItem}.
	 */
	void onDataItem(DataItem dataItem);

}
