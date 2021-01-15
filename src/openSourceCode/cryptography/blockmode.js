/*!
 * Crypto-JS 2.5.4 BlockModes.js
 * contribution from Simon Greatrix
 */

(function () {
	// create pad namespace
	globalThis.__Crypto__.pad = {};
	/**
	 * @description
	 *  Calculate the number of padding bytes required
	 */
	function _requiredPadding(cipher, message) {
		var blockSizeInBytes = cipher._blocksize * 4;
		var reqd = blockSizeInBytes - (message.length % blockSizeInBytes);
		return reqd;
	}

	/**
	 * @description
	 * Remove padding when the final byte gives the number of padding bytes.*/
	function _unpadLength(cipher, message, alg, padding) {
		var pad = message.pop();
		if (pad == 0) {
			throw new Error(
				'Invalid zero-length padding specified for ' + alg + '. Wrong cipher specification or key used?'
			);
		}
		var maxPad = cipher._blocksize * 4;
		if (pad > maxPad) {
			throw new Error(
				'Invalid padding length of ' +
					pad +
					' specified for ' +
					alg +
					'. Wrong cipher specification or key used?'
			);
		}
		for (var i = 1; i < pad; i++) {
			var b = message.pop();
			if (padding != undefined && padding != b) {
				throw new Error(
					'Invalid padding byte of 0x' +
						b.toString(16) +
						' specified for ' +
						alg +
						'. Wrong cipher specification or key used?'
				);
			}
		}
	}
	/**
	 * @description
	 * No-operation padding, used for stream ciphers
	 */
	globalThis.__Crypto__.pad.NoPadding = {
		pad(cipher, message) {},
		unpad(cipher, message) {},
	};

	/**
	 * @description
	 * Zero Padding
	 * If the message is not an exact number of blocks, the final block is
	 * completed with 0x00 bytes. There is no unpadding.
	 */
	globalThis.__Crypto__.pad.ZeroPadding = {
		pad(cipher, message) {
			var blockSizeInBytes = cipher._blocksize * 4;
			var reqd = message.length % blockSizeInBytes;
			if (reqd != 0) {
				for (reqd = blockSizeInBytes - reqd; reqd > 0; reqd--) {
					message.push(0x00);
				}
			}
		},
		unpad(cipher, message) {
			while (message[message.length - 1] == 0) {
				message.pop();
			}
		},
	};
	/**
	 * @description
	 *  ISO/IEC 7816-4 padding.
	 *  Pads the plain text with an 0x80 byte followed by as many 0x00
	 *  bytes are required to complete the block.
	 */
	globalThis.__Crypto__.pad.iso7816 = {
		pad(cipher, message) {
			var blockSizeInBytes = cipher._blocksize * 4;
			var reqd = message.length % blockSizeInBytes;
			if (reqd != 0) {
				for (reqd = blockSizeInBytes - reqd; reqd > 0; reqd--) {
					message.push(0x00);
				}
			}
		},
		unpad(cipher, message) {
			var padLength;
			for (padLength = cipher._blocksize * 4; padLength > 0; padLength--) {
				var b = message.pop();
				if (b == 0x80) return;
				if (b != 0x00) {
					throw new Error(
						'ISO-7816 padding byte must be 0, not 0x' +
							b.toString(16) +
							'. Wrong cipher specification or key used?'
					);
				}
			}
			throw new Error('ISO-7816 padded beyond cipher block size. Wrong cipher specification or key used?');
		},
	};
	/**
	 * @description
	 * ANSI X.923 padding
	 * The final block is padded with zeros except for the last byte of the
	 * last block which contains the number of padding bytes.
	 *
	 */
	globalThis.__Crypto__.pad.ansix923 = {
		pad(cipher, message) {
			var reqd = _requiredPadding(cipher, message);
			for (var i = 1; i < reqd; i++) {
				message.push(0x00);
			}
			message.push(reqd);
		},

		unpad: function (cipher, message) {
			_unpadLength(cipher, message, 'ANSI X.923', 0);
		},
	};
	/**
	 * @description
	 * ISO 10126
	 *
	 * The final block is padded with random bytes except for the last
	 *  byte of the last block which contains the number of padding bytes.
	 */
	globalThis.__Crypto__.pad.iso10126 = {
		pad(cipher, message) {
			var reqd = _requiredPadding(cipher, message);
			for (var i = 1; i < reqd; i++) {
				message.push(Math.floor(Math.random() * 256));
			}
			message.push(reqd);
		},
		unpad(cipher, message) {
			_unpadLength(cipher, message, 'ISO 10126', undefined);
		},
	};

	/**
	 * @description
	 * PKCS7 padding
	 *
	 * PKCS7 is described in RFC 5652. Padding is in whole bytes.
	 * The value of each added byte is the number of bytes that are added,
	 * i.e. N bytes, each of value N are added.
	 */
	globalThis.__Crypto__.pad.pkcs7 = {
		pad(cipher, message) {
			var reqd = _requiredPadding(cipher, message);
			for (var i = 0; i < reqd; i++) {
				message.push(reqd);
			}
		},
		unpad(cipher, message) {
			_unpadLength(cipher, message, 'PKCS 7', message[message.length - 1]);
		},
	};

	// create mode namespace
	globalThis.__Crypto__.mode = {};

	globalThis.__Crypto__.mode.Mode = function (padding) {
		if (padding) {
			this._padding = padding;
		}
	};

	globalThis.__Crypto__.mode.Mode.prototype = {
		encrypt(cipher, m, iv) {
			this._padding.pad(cipher, m);
			this._doEncrypt(cipher, m, iv);
		},
		decrypt(cipher, m, iv) {
			this._doDecrypt(cipher, m, iv);
			this._padding.unpad(cipher, m);
		},
		// default padding
		_padding: globalThis.__Crypto__.pad.iso7816,
	};

	/**
	 * @description
	 * Electronic Code Book mode.
	 *
	 * ECB applies the cipher directly against each block of the input.
	 *
	 * ECB does not require an initialization vector.
	 */
	globalThis.__Crypto__.mode.ECB = function () {
		// Call parent constructor
		globalThis.__Crypto__.mode.Mode.apply(this, arguments);
	};
	// Inherit from Mode.
	globalThis.__Crypto__.mode.ECB.prototype = new globalThis.__Crypto__.mode.Mode();

	// Concrete steps for Mode template
	globalThis.__Crypto__.mode.ECB.prototype._doEncrypt = function (cipher, m, iv) {
		var blockSizeInBytes = cipher._blocksize * 4;
		// Encrypt each block
		for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
			cipher._encryptblock(m, offset);
		}
	};

	globalThis.__Crypto__.mode.ECB.prototype._doDecrypt = function (cipher, c, iv) {
		var blockSizeInBytes = cipher._blocksize * 4;
		// Decrypt each block
		for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
			cipher._decryptblock(c, offset);
		}
	};
	// ECB never uses an IV
	globalThis.__Crypto__.mode.ECB.prototype.fixOptions = function (options) {
		options.iv = [];
	};

	/**
	 * @description
	 * Cipher block chaining
	 *
	 * The first block is XORed with the IV. Subsequent blocks are XOR with the
	 * previous cipher output.
	 */
	globalThis.__Crypto__.mode.CBC = function () {
		// Call parent constructor
		globalThis.__Crypto__.mode.Mode.apply(this, arguments);
	};

	// Inherit from Mode
	globalThis.__Crypto__.mode.CBC.prototype = new globalThis.__Crypto__.mode.Mode();
	// Concrete steps for Mode template
	globalThis.__Crypto__.mode.CBC.prototype._doEncrypt = function (cipher, m, iv) {
		var blockSizeInBytes = cipher._blocksize * 4;

		// Encrypt each block
		for (var offset = 0; offset < m.length; offset += blockSizeInBytes) {
			if (offset == 0) {
				// XOR first block using IV
				for (var i = 0; i < blockSizeInBytes; i++) m[i] ^= iv[i];
			} else {
				// XOR this block using previous crypted block
				for (var i = 0; i < blockSizeInBytes; i++) m[offset + i] ^= m[offset + i - blockSizeInBytes];
			}
			// Encrypt block
			cipher._encryptblock(m, offset);
		}
	};

	globalThis.__Crypto__.mode.CBC.prototype._doDecrypt = function (cipher, c, iv) {
		var blockSizeInBytes = cipher._blocksize * 4;

		// At the start, the previously crypted block is the IV
		var prevCryptedBlock = iv;

		// Decrypt each block
		for (var offset = 0; offset < c.length; offset += blockSizeInBytes) {
			// Save this crypted block
			var thisCryptedBlock = c.slice(offset, offset + blockSizeInBytes);
			// Decrypt block
			cipher._decryptblock(c, offset);
			// XOR decrypted block using previous crypted block
			for (var i = 0; i < blockSizeInBytes; i++) {
				c[offset + i] ^= prevCryptedBlock[i];
			}
			prevCryptedBlock = thisCryptedBlock;
		}
	};

	/**
	 * @description
	 * Cipher feed back
	 *
	 * The cipher output is XORed with the plain text to produce the cipher output,
	 * which is then fed back into the cipher to produce a bit pattern to XOR the
	 * next block with.
	 *
	 * This is a stream cipher mode and does not require padding.
	 */
	globalThis.__Crypto__.mode.CFB = function () {
		// Call parent constructor
		globalThis.__Crypto__.mode.Mode.apply(this, arguments);
	};

	// Inherit from Mode
	globalThis.__Crypto__.mode.CFB.prototype = new globalThis.__Crypto__.mode.Mode();

	// Override padding
	globalThis.__Crypto__.mode.CFB.prototype._padding = globalThis.__Crypto__.pad.NoPadding;

	// Concrete steps for Mode template
	globalThis.__Crypto__.mode.CFB.prototype._doEncrypt = function (cipher, m, iv) {
		var blockSizeInBytes = cipher._blocksize * 4,
			keystream = iv.slice(0);

		// Encrypt each byte
		for (var i = 0; i < m.length; i++) {
			var j = i % blockSizeInBytes;
			if (j == 0) cipher._encryptblock(keystream, 0);

			m[i] ^= keystream[j];
			keystream[j] = m[i];
		}
	};
	globalThis.__Crypto__.mode.CFB.prototype._doDecrypt = function (cipher, c, iv) {
		var blockSizeInBytes = cipher._blocksize * 4,
			keystream = iv.slice(0);

		// Encrypt each byte
		for (var i = 0; i < c.length; i++) {
			var j = i % blockSizeInBytes;
			if (j == 0) cipher._encryptblock(keystream, 0);

			var b = c[i];
			c[i] ^= keystream[j];
			keystream[j] = b;
		}
	};

	/**
	 * @description
	 * Output feed back
	 *
	 * The cipher repeatedly encrypts its own output. The output is XORed with the
	 * plain text to produce the cipher text.
	 *
	 * This is a stream cipher mode and does not require padding.
	 */
	globalThis.__Crypto__.mode.OFB = function () {
		// Call parent constructor
		globalThis.__Crypto__.mode.Mode.apply(this, arguments);
	};
	// Inherit from Mode
	globalThis.__Crypto__.mode.OFB.prototype = new globalThis.__Crypto__.mode.Mode();

	// Override padding
	globalThis.__Crypto__.mode.OFB.prototype._padding = globalThis.__Crypto__.pad.NoPadding;

	// Concrete steps for Mode template
	globalThis.__Crypto__.mode.OFB.prototype._doEncrypt = function (cipher, m, iv) {
		var blockSizeInBytes = cipher._blocksize * 4,
			keystream = iv.slice(0);

		// Encrypt each byte
		for (var i = 0; i < m.length; i++) {
			// Generate keystream
			if (i % blockSizeInBytes == 0) cipher._encryptblock(keystream, 0);

			// Encrypt byte
			m[i] ^= keystream[i % blockSizeInBytes];
		}
	};

	globalThis.__Crypto__.mode.OFB.prototype._doDecrypt = globalThis.__Crypto__.mode.OFB.prototype._doEncrypt;

	/**
	 * Counter
	 * @author Gergely Risko
	 *
	 * After every block the last 4 bytes of the IV is increased by one
	 * with carry and that IV is used for the next block.
	 *
	 * This is a stream cipher mode and does not require padding.
	 */
	globalThis.__Crypto__.mode.CTR = function () {
		// Call parent constructor
		globalThis.__Crypto__.mode.Mode.apply(this, arguments);
	};

	// Inherit from Mode
	globalThis.__Crypto__.mode.CTR.prototype = new globalThis.__Crypto__.mode.Mode();

	// Override padding
	globalThis.__Crypto__.mode.CTR.prototype._padding = globalThis.__Crypto__.pad.NoPadding;

	globalThis.__Crypto__.mode.CTR.prototype._doEncrypt = function (cipher, m, iv) {
		var blockSizeInBytes = cipher._blocksize * 4;
		var counter = iv.slice(0);

		for (var i = 0; i < m.length; ) {
			// do not lose iv
			var keystream = counter.slice(0);

			// Generate keystream for next block
			cipher._encryptblock(keystream, 0);

			// XOR keystream with block
			for (var j = 0; i < m.length && j < blockSizeInBytes; j++, i++) {
				m[i] ^= keystream[j];
			}

			// Increase counter
			if (++counter[blockSizeInBytes - 1] == 256) {
				counter[blockSizeInBytes - 1] = 0;
				if (++counter[blockSizeInBytes - 2] == 256) {
					counter[blockSizeInBytes - 2] = 0;
					if (++counter[blockSizeInBytes - 3] == 256) {
						counter[blockSizeInBytes - 3] = 0;
						++counter[blockSizeInBytes - 4];
					}
				}
			}
		}
	};
	globalThis.__Crypto__.mode.CTR.prototype._doDecrypt = globalThis.__Crypto__.mode.CTR._doEncrypt;
})();
