(function () {
	var { util, charenc } = globalThis.__Crypto__,
		{ UTF8, Binary } = charenc;

	globalThis.__Crypto__.PBKDF2 = function (password, salt, keylen, options) {
		// Convert to byte arrays
		if (typeof password === 'string') password = UTF8.stringToBytes(password);
		if (typeof salt === 'string') salt = UTF8.stringToBytes(salt);
		/* else, assume byte arrays already */

		// Defaults
		var hasher = (options && options.hasher) || C.SHA1,
			iterations = (options && options.iterations) || 1;

		// Pseudo-random function
		function PRF(password, salt) {
			return C.HMAC(hasher, salt, password, { asBytes: true });
		}

		// Generate key
		var derivedKeyBytes = [],
			blockindex = 1;
		while (derivedKeyBytes.length < keylen) {
			var block = PRF(password, salt.concat(util.wordsToBytes([blockindex])));
			for (var u = block, i = 1; i < iterations; i++) {
				u = PRF(password, u);
				for (var j = 0; j < block.length; j++) block[j] ^= u[j];
			}
			derivedKeyBytes = derivedKeyBytes.concat(block);
			blockindex++;
		}

		// Truncate excess bytes
		derivedKeyBytes.length = keylen;

		return options && options.asBytes
			? derivedKeyBytes
			: options && options.asString
			? Binary.bytesToString(derivedKeyBytes)
			: util.bytesToHex(derivedKeyBytes);
	};
})();
