[
	'./src/openSourceCode/cryptography/crypto.js',
	'./src/openSourceCode/cryptography/sha256.js',
	'./src/openSourceCode/cryptography/pbkdf2.js',
	'./src/openSourceCode/cryptography/hmac.js',
	'./src/openSourceCode/cryptography/aes.js',
	'./src/openSourceCode/cryptography/blockmode.js',
	'./src/openSourceCode/cryptography/ripemd160.js',
	'./src/openSourceCode/random/secureRandom.js',
	'./src/openSourceCode/elipticcurve/ec.js',
	'./src/openSourceCode/secrets/se.js',
	'./src/openSourceCode/numbers/bigInteger.js',
	'./src/openSourceCode/bitcoin_lib/init.js',
	'./src/openSourceCode/bitcoin_lib/base58.js',
	'./src/openSourceCode/bitcoin_lib/address.js',
	'./src/openSourceCode/bitcoin_lib/ecdsa.js',
	'./src/openSourceCode/bitcoin_lib/eckey.js',
	'./src/openSourceCode/bitcoin_lib/util.js',
	'./src/openSourceCode/bitcoin_lib/crypto-scrypt.js',
	'./src/generate.js',
].forEach((url) => {
	var script = document.createElement('script');
	script.setAttribute('src', url);
	script.setAttribute('type', 'text/javascript');
	script.setAttribute('defer', true);
	document.querySelector('head').appendChild(script);
});
