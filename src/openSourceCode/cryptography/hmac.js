/*!
 * Crypto-JS v2.5.4	HMAC.js
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009-2013, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function () {
	var { util, charenc } = globalThis.__Crypto__,
		{ UTF8, Binary } = charenc;
	globalThis.__Crypto__.HMAC = function (hasher, message, key, options) {
		// Convert to byte arrays
		if (typeof message === 'string') message = UTF8.stringToBytes(message);
		if (typeof key === 'string') key = UTF8.stringToBytes(key);
		/* else, assume byte arrays already */

		// Allow arbitrary length keys
		if (key.length > hasher._blocksize * 4) key = hasher(key, { asBytes: true });

		// XOR keys with pad constants
		var okey = key.slice(0),
			ikey = key.slice(0);
		for (var i = 0; i < hasher._blocksize * 4; i++) {
			okey[i] ^= 0x5c;
			ikey[i] ^= 0x36;
		}

		var hmacbytes = hasher(okey.concat(hasher(ikey.concat(message), { asBytes: true })), { asBytes: true });

		return options && options.asBytes
			? hmacbytes
			: options && options.asString
			? Binary.bytesToString(hmacbytes)
			: util.bytesToHex(hmacbytes);
	};
})();
