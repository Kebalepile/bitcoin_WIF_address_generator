/*!
 * Random number generator with ArcFour PRNG
 *
 * NOTE: For best results, put code like
 * <body onclick='SecureRandom.seedTime();' onkeypress='SecureRandom.seedTime();'>
 * in your main HTML document.
 *
 * Copyright Tom Wu, bitaddress.org  BSD License.
 * http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE
 */

(function () {
	globalThis.SecureRandom = function () {};

	// Properties
	SecureRandom.state;
	SecureRandom.pool;
	SecureRandom.pptr;
	SecureRandom.poolCopyOnInit;

	// Pool size must be a multiple of 4 and greater than 32.
	// An array of bytes the size of the pool will be passed to init()
	SecureRandom.poolSize = 256;

	// --- object methods ---

	// public method
	// ba: byte array
	SecureRandom.prototype.nextBytes = function (ba) {
		var i;

		try {
			var rvBytes = new Uint8Array(ba.length);
			crypto.getRandomValues(rvBytes);
			for (i = 0; i < ba.length; ++i) ba[i] = SecureRandom.getByte() ^ rvBytes[i];
			return;
		} catch (e) {
			alert(e);
		}

		for (i = 0; i < ba.length; ++i) ba[i] = SecureRandom.getByte();
	};

	// --- static methods ---

	// Mix in the current time (w/milliseconds) into the pool
	// NOTE: this method should be called from body click/keypress event handlers to increase entropy
	SecureRandom.seedTime = function () {
		SecureRandom.seedInt(new Date().getTime());
	};

	SecureRandom.getByte = function () {
		if (SecureRandom.state == null) {
			SecureRandom.seedTime();
			SecureRandom.state = SecureRandom.ArcFour(); // Plug in your RNG constructor here
			SecureRandom.state.init(SecureRandom.pool);
			SecureRandom.poolCopyOnInit = [];
			for (
				SecureRandom.pptr = 0;
				SecureRandom.pptr < SecureRandom.pool.length;
				++SecureRandom.pptr
			)
				SecureRandom.poolCopyOnInit[SecureRandom.pptr] =
					SecureRandom.pool[SecureRandom.pptr];
			SecureRandom.pptr = 0;
		}
		// TODO: allow reseeding after first request
		return SecureRandom.state.next();
	};

	// Mix in a 32-bit integer into the pool
	SecureRandom.seedInt = function (x) {
		SecureRandom.seedInt8(x);
		SecureRandom.seedInt8(x >> 8);
		SecureRandom.seedInt8(x >> 16);
		SecureRandom.seedInt8(x >> 24);
	};

	// Mix in a 16-bit integer into the pool
	SecureRandom.seedInt16 = function (x) {
		SecureRandom.seedInt8(x);
		SecureRandom.seedInt8(x >> 8);
	};

	// Mix in a 8-bit integer into the pool
	SecureRandom.seedInt8 = function (x) {
		SecureRandom.pool[SecureRandom.pptr++] ^= x & 255;
		if (SecureRandom.pptr >= SecureRandom.poolSize)
			SecureRandom.pptr -= SecureRandom.poolSize;
	};

	// Arcfour is a PRNG
	SecureRandom.ArcFour = function () {
		function Arcfour() {
			this.i = 0;
			this.j = 0;
			this.S = new Array();
		}

		// Initialize arcfour context from key, an array of ints, each from [0..255]
		function ARC4init(key) {
			var i, j, t;
			for (i = 0; i < 256; ++i) this.S[i] = i;
			j = 0;
			for (i = 0; i < 256; ++i) {
				j = (j + this.S[i] + key[i % key.length]) & 255;
				t = this.S[i];
				this.S[i] = this.S[j];
				this.S[j] = t;
			}
			this.i = 0;
			this.j = 0;
		}

		function ARC4next() {
			var t;
			this.i = (this.i + 1) & 255;
			this.j = (this.j + this.S[this.i]) & 255;
			t = this.S[this.i];
			this.S[this.i] = this.S[this.j];
			this.S[this.j] = t;
			return this.S[(t + this.S[this.i]) & 255];
		}

		Arcfour.prototype.init = ARC4init;
		Arcfour.prototype.next = ARC4next;

		return new Arcfour();
	};

	// Initialize the pool with junk if needed.
	if (SecureRandom.pool == null) {
		SecureRandom.pool = new Array();
		SecureRandom.pptr = 0;
		var t;

		try {
			// Use webcrypto if available
			var ua = new Uint8Array(SecureRandom.poolSize);
			crypto.getRandomValues(ua);
			for (t = 0; t < SecureRandom.poolSize; ++t)
				SecureRandom.pool[SecureRandom.pptr++] = ua[t];
		} catch (e) {
			alert(e);
		}

		while (SecureRandom.pptr < SecureRandom.poolSize) {
			// extract some randomness from Math.random()
			t = Math.floor(65536 * Math.random());
			SecureRandom.pool[SecureRandom.pptr++] = t >>> 8;
			SecureRandom.pool[SecureRandom.pptr++] = t & 255;
		}
		SecureRandom.pptr = Math.floor(SecureRandom.poolSize * Math.random());
		SecureRandom.seedTime();
		// entropy
		var entropyStr = '';
		// screen size and color depth: ~4.8 to ~5.4 bits
		entropyStr += window.screen.height * window.screen.width * window.screen.colorDepth;
		entropyStr += window.screen.availHeight * window.screen.availWidth * window.screen.pixelDepth;
		// time zone offset: ~4 bits
		var dateObj = new Date();
		var timeZoneOffset = dateObj.getTimezoneOffset();
		entropyStr += timeZoneOffset;
		// user agent: ~8.3 to ~11.6 bits
		entropyStr += navigator.userAgent;
		// browser plugin details: ~16.2 to ~21.8 bits
		var pluginsStr = '';
		for (var i = 0; i < navigator.plugins.length; i++) {
			pluginsStr +=
				navigator.plugins[i].name +
				' ' +
				navigator.plugins[i].filename +
				' ' +
				navigator.plugins[i].description +
				' ' +
				navigator.plugins[i].version +
				', ';
		}
		var mimeTypesStr = '';
		for (var i = 0; i < navigator.mimeTypes.length; i++) {
			mimeTypesStr +=
				navigator.mimeTypes[i].description +
				' ' +
				navigator.mimeTypes[i].type +
				' ' +
				navigator.mimeTypes[i].suffixes +
				', ';
		}
		entropyStr += pluginsStr + mimeTypesStr;
		// cookies and storage: 1 bit
		entropyStr += navigator.cookieEnabled + typeof sessionStorage + typeof localStorage;
		// language: ~7 bit
		entropyStr += navigator.language;
		// history: ~2 bit
		entropyStr += window.history.length;
		// location
		entropyStr += window.location;

		var entropyBytes = __Crypto__.SHA256(entropyStr, { asBytes: true });
		for (var i = 0; i < entropyBytes.length; i++) {
			SecureRandom.seedInt8(entropyBytes[i]);
		}
	}
})();
