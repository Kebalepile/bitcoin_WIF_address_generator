/*!
 * Crypto-JS v2.5.4	Crypto.js
 * http://code.google.com/p/crypto-js/
 * Copyright (c) 2009-2013, Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(function () {
	var base64map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	globalThis.__Crypto__ = {
		util: {
			/**
			 *
			 * @param {*} n
			 * @param {number} b
			 * @description Bit-wise rotate left
			 */
			rotl: (n, b) => (n << b) | (n >>> (32 - b)),
			/**
			 *
			 * @param {*} n
			 * @param {number} b
			 * @description Bit-wise rotate right
			 */
			rotr: (n, b) => (n << (32 - b)) | (n >>> b),
			/**
			 *
			 * @param {*} n
			 * @description Swap big-endian to little-endian and vice versa
			 */
			endian(n) {
				// if given number, swap endian
				if (typeof n === 'number') {
					return (this.rotl(n, 8) & 0x00ff00ff) | (this.rotl(n, 24) & 0xff00ff00);
				}

				// Else, assume array and swap all items
				for (var i = 0; i < n.length; i++) n[i] = this.endian(n[i]);
				return n;
			},
			/**
			 * @param {number} n
			 * @description
			 * Generate an array of any length of random bytes
			 */
			randomBytes(n) {
				for (var bytes = []; n > 0; n--) bytes.push(Math.floor(Math.random() * 256));
				return bytes;
			},
			/**
			 *
			 * @param {array} bytes
			 * @description
			 * Convert a byte array to big-endian 32-bit words
			 */
			bytesToWords(bytes) {
				for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
					words[b >>> 5] |= (bytes[i] & 0xff) << (24 - (b % 32));
				return words;
			},
			/**
			 *
			 * @param {string} words
			 * @description
			 * Convert big-endian 32-bit words to a byte array
			 */
			wordsToBytes(words) {
				for (var bytes = [], b = 0; b < words.length * 32; b += 8)
					bytes.push((words[b >>> 5] >>> (24 - (b % 32))) & 0xff);
				return bytes;
			},
			/**
			 *
			 * @param {array} bytes
			 * @description
			 * Convert a byte array to a hex string
			 */
			bytesToHex(bytes) {
				for (var hex = [], i = 0; i < bytes.length; i++) {
					hex.push((bytes[i] >>> 4).toString(16));
					hex.push((bytes[i] & 0xf).toString(16));
				}
				return hex.join('');
			},
			/**
			 * @param {string} hex
			 * @description
			 * Convert a hex string to a byte array
			 */
			hexToBytes(hex) {
				for (var bytes = [], c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
				return bytes;
			},
			/**
			 *
			 * @param {array} bytes
			 * @description Convert a byte array to a base-64 string
			 */
			bytesToBase64(bytes) {
				for (var base64 = [], i = 0; i < bytes.length; i += 3) {
					var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
					for (var j = 0; j < 4; j++) {
						if (i * 8 + j * 6 <= bytes.length * 8)
							base64.push(base64map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
						else base64.push('=');
					}
				}

				return base64.join('');
			},
			/**
			 *
			 * @param {string} base64
			 * @description
			 * Convert a base-64 string to a byte array
			 */
			base64ToBytes(base64) {
				// Remove non-base-64 characters
				base64 = base64.replace(/[^A-Z0-9+\/]/gi, '');

				for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
					if (imod4 == 0) continue;
					bytes.push(
						((base64map.indexOf(base64.charAt(i - 1)) & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2)) |
							(base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2))
					);
				}

				return bytes;
			},
		},
		charenc: {
			UTF8: {
				/**
				 *
				 * @param {string} str
				 * @description
				 * convert string to bytes array
				 */
				stringToBytes: (str) =>
					globalThis.__Crypto__.charenc.Binary.stringToBytes(unescape(encodeURIComponent(str))),
				/**
				 *
				 * @param {array} bytes
				 * convert a bytes array to string
				 */
				bytesToString: (bytes) =>
					decodeURIComponent(escape(globalThis.__Crypto__.charenc.Binary.bytesToString(bytes))),
			},
			Binary: {
				/**
				 *
				 * @param {string} str
				 * @description
				 * Convert a string to a byte array
				 */
				stringToBytes(str) {
					for (var bytes = [], i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i) & 0xff);
					return bytes;
				},
				/**
				 *
				 * @param {array} bytes
				 * Convert a byte array to a string
				 */
				bytesToString(bytes) {
					for (var str = [], i = 0; i < bytes.length; i++) str.push(String.fromCharCode(bytes[i]));
					return str.join('');
				},
			},
		},
	};
})();
