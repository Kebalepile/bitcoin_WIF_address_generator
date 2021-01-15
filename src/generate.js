(function () {
	globalThis.seeder = {
		/**
		 * @description
		 * number of mouse movements to wait for
		 */
		seedLimit: 200 + Math.floor(crypto.getRandomValues(new Uint8Array(1))[0]),
		/**
		 * @description counter
		 */
		seedCount: 0,
		lastInputTime: new Date().getTime(),
		seedPoints: [],
		isStillSeeding: true,
		seederDependentWallets: ['singlewallet', 'paperwallet', 'bulkwallet', 'vanitywallet', 'splitwallet'],
		/**
		 *
		 * @param {event} e
		 * @description
		 * wait for mouse movement to add
		 * extra randomness before generating an address
		 */
		seed(e) {
			let timeStamp = new Date().getTime();
			/**
			 * seeding is over, generate and display address
			 */
			if (Math.round((seeder.seedCount / seeder.seedLimit) * 100) === 100) {
				gene = false;
				seeder.seedCount++;
				seeder.seedingOver();
			} else if (seeder.seedCount < seeder.seedLimit && e && timeStamp - seeder.lastInputTime > 40) {
				SecureRandom.seedTime();
				SecureRandom.seedInt16(e.clientX * e.clientY);
				seeder.showPoint(e.clientX, e.clientY);
				seeder.seedCount++;
				seeder.lastInputTime = new Date().getTime();
				seeder.showPool();
			}
		},
		showPool() {
			var poolHex;
			if (SecureRandom.poolCopyOnInit) {
				poolHex = __Crypto__.util.bytesToHex(SecureRandom.poolCopyOnInit);
				console.log('pool hex: ', poolHex);
			} else {
				poolHex = __Crypto__.util.bytesToHex(globalThis.SecureRandom.pool);
				console.log('pool hex: ', poolHex);
			}

			var precentSeeded = Math.round((this.seedCount / this.seedLimit) * 100);
			console.log('seeded about: ', precentSeeded);
			console.log('seeded about ', precentSeeded, '% of ', this.seederDependentWallets[0]);
			console.log('seed count ', this.seedCount);
			console.log('seed limit ', this.seedLimit);
			// for (var wallet in this.seederDependentWallets) {
			// 	console.log('seeded about ', precentSeeded, '% of ', this.seederDependentWallets[0];
			// }
		},
		showPoint(x, y) {
			console.log('x-axis ', x);
			console.log('y-axis ', y);
		},
		seedingOver() {
			this.isStillSeeding = false;
			try {
				let key = new Bitcoin.ECKey(false);
				key.setCompressed(true);
				let btcAddress = key.getBitcoinAddress();
				let btcPrivateWIF = key.getBitcoinWalletImportFormat();
				console.log('btc address, ', btcAddress);
				console.log('btc private WIF key, ', btcPrivateWIF);
				// QRCode
			} catch (e) {
				console.error(e);
			}
		},
	};

	document.body.querySelector('#generateWIF').addEventListener('click', (e) => {
		// disable button temporarily
		SecureRandom.seedTime();
		if(gene !== true) gene = true;
		while (gene) {
			let clientX = crypto.getRandomValues(new Uint16Array(1))[0],
				clientY = crypto.getRandomValues(new Uint16Array(1))[0];

			seeder.seed({
				clientX,
				clientY,
			});
		}
	});

	globalThis.gene = true;

})();
