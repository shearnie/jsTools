/// <reference path="Scripts/typings/jquery/jquery.d.ts" />

// jsTools (shearnie.tools)
// A little toolbox for my little brain
// https://github.com/shearnie/jsTools

module shearnie.tools {

	/*************************************************************************************************
	 * Tidy one-liners for ajax posting
	 */
	export class PostData {
		public url: string;
		public data: any;
		public hashid: string;
		public result: any;
		public error: any;
		constructor(url: string, data?: any) {
			this.url = url;
			this.data = data;
			// generate hash of url for identification
			this.hashid = new Md5().md5(url);
		}
	}

	export class Poster {
		// Syncronous, return object
		SendSync(url: string, data?: any) {
			if (url == null || url == '') throw 'No target.';

			var obj = null;
			var error = null;

			var setobj = (result) => {
				obj = result;
			}

			var seterr = (err) => {
				error = err;
			}

			$.when(
				$.ajax({
					type: 'POST',
					url: url,
					data: data,
					dataType: "json",
					async: false
				}))
				.then(
				result => {
					setobj(result);
				},
				err => {
					seterr(err);
				});

			if (error != null) throw error;
			return obj;
		}

		/* send multiple requests as async
		 * usage:
			var pd = new Array();
			pd[0] = new PostData('url/to/post/to', { name: "Steve" });
			pd[1] = new PostData('url/to/post/to', { name: "Ada" });
			pd[2] = new PostData('url/to/post/to', { name: "Ebi" });
	
			new shearnie.tools.Poster().SendAsync(pd, function(numErrs) {
				console.log(numErrs + ' errors');
				console.log(pd[2].result);
			});
		 */
		SendAsync(postData: PostData[], onCompleted: (numErrs: number) => void) {
			if (postData == null) throw 'No target/s.';
			if (postData.length == 0) throw 'No target/s.';

			// post all requests
			var errCount: number = 0;
			postData.forEach((pd) => {
				pd.result = null; pd.error = null;
				$.when(
					$.ajax({
						type: 'POST',
						url: pd.url,
						data: pd.data,
						dataType: "json",
						async: true
					}))
					.then(
					result => {
						pd.result = result;
						if (!this.checkAnyEmpty(postData)) onCompleted(errCount);
					},
					err => {
						pd.error = err;
						errCount++;
						if (!this.checkAnyEmpty(postData)) onCompleted(errCount);
					});
			});
		}

		private checkAnyEmpty(postData: PostData[]): boolean {
			var ret = false;
			postData.every((pd) => {
				if (pd.result == null) // no result
					if (pd.error == null) { // or error
						ret = true; // still empty
						return false;
					}
				return true;
			});
			return ret;
		}

		public findPostData(postData: PostData[], hashToMatch: string): PostData {
			var ret: PostData = null;
			postData.every((pd) => {
				if (pd.hashid == hashToMatch) {
					ret = pd;
					return false;
				}
				return true;
			});
			return ret;
		}
	}
	
	//#region "Md5"

	/*************************************************************************************************
	 * JavaScript MD5 1.0
	 * https://github.com/blueimp/JavaScript-MD5
	 *
	 * Copyright 2011, Sebastian Tschan
	 * https://blueimp.net
	 *
	 * Licensed under the MIT license:
	 * http://www.opensource.org/licenses/MIT
	 * 
	 * Based on
	 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
	 * Digest Algorithm, as defined in RFC 1321.
	 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
	 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
	 * Distributed under the BSD License
	 * See http://pajhome.org.uk/crypt/md5 for more info.
	 */
	export class Md5 {
		/*jslint bitwise: true */
		/*global unescape, define */

		/*
		* Add integers, wrapping at 2^32. This uses 16-bit operations internally
		* to work around bugs in some JS interpreters.
		*/
		private safe_add(x, y) {
			var lsw = (x & 0xFFFF) + (y & 0xFFFF),
				msw = (x >> 16) + (y >> 16) + (lsw >> 16);
			return (msw << 16) | (lsw & 0xFFFF);
		}

		/*
		* Bitwise rotate a 32-bit number to the left.
		*/
		private bit_rol(num, cnt) {
			return (num << cnt) | (num >>> (32 - cnt));
		}

		/*
		* These functions implement the four basic operations the algorithm uses.
		*/
		private md5_cmn(q, a, b, x, s, t) {
			return this.safe_add(this.bit_rol(this.safe_add(this.safe_add(a, q), this.safe_add(x, t)), s), b);
		}
		private md5_ff(a, b, c, d, x, s, t) {
			return this.md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
		}
		private md5_gg(a, b, c, d, x, s, t) {
			return this.md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
		}
		private md5_hh(a, b, c, d, x, s, t) {
			return this.md5_cmn(b ^ c ^ d, a, b, x, s, t);
		}
		private md5_ii(a, b, c, d, x, s, t) {
			return this.md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
		}

		/*
		* Calculate the MD5 of an array of little-endian words, and a bit length.
		*/
		private binl_md5(x, len) {
			/* append padding */
			x[len >> 5] |= 0x80 << ((len) % 32);
			x[(((len + 64) >>> 9) << 4) + 14] = len;

			var i, olda, oldb, oldc, oldd,
				a = 1732584193,
				b = -271733879,
				c = -1732584194,
				d = 271733878;

			for (i = 0; i < x.length; i += 16) {
				olda = a;
				oldb = b;
				oldc = c;
				oldd = d;

				a = this.md5_ff(a, b, c, d, x[i], 7, -680876936);
				d = this.md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
				c = this.md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
				b = this.md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
				a = this.md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
				d = this.md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
				c = this.md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
				b = this.md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
				a = this.md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
				d = this.md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
				c = this.md5_ff(c, d, a, b, x[i + 10], 17, -42063);
				b = this.md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
				a = this.md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
				d = this.md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
				c = this.md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
				b = this.md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

				a = this.md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
				d = this.md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
				c = this.md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
				b = this.md5_gg(b, c, d, a, x[i], 20, -373897302);
				a = this.md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
				d = this.md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
				c = this.md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
				b = this.md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
				a = this.md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
				d = this.md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
				c = this.md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
				b = this.md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
				a = this.md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
				d = this.md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
				c = this.md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
				b = this.md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

				a = this.md5_hh(a, b, c, d, x[i + 5], 4, -378558);
				d = this.md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
				c = this.md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
				b = this.md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
				a = this.md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
				d = this.md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
				c = this.md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
				b = this.md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
				a = this.md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
				d = this.md5_hh(d, a, b, c, x[i], 11, -358537222);
				c = this.md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
				b = this.md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
				a = this.md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
				d = this.md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
				c = this.md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
				b = this.md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

				a = this.md5_ii(a, b, c, d, x[i], 6, -198630844);
				d = this.md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
				c = this.md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
				b = this.md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
				a = this.md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
				d = this.md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
				c = this.md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
				b = this.md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
				a = this.md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
				d = this.md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
				c = this.md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
				b = this.md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
				a = this.md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
				d = this.md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
				c = this.md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
				b = this.md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

				a = this.safe_add(a, olda);
				b = this.safe_add(b, oldb);
				c = this.safe_add(c, oldc);
				d = this.safe_add(d, oldd);
			}
			return [a, b, c, d];
		}

		/*
		* Convert an array of little-endian words to a string
		*/
		private binl2rstr(input) {
			var i,
				output = '';
			for (i = 0; i < input.length * 32; i += 8) {
				output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
			}
			return output;
		}

		/*
		* Convert a raw string to an array of little-endian words
		* Characters >255 have their high-byte silently ignored.
		*/
		private rstr2binl(input) {
			var i,
				output = [];
			output[(input.length >> 2) - 1] = undefined;
			for (i = 0; i < output.length; i += 1) {
				output[i] = 0;
			}
			for (i = 0; i < input.length * 8; i += 8) {
				output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
			}
			return output;
		}

		/*
		* Calculate the MD5 of a raw string
		*/
		private rstr_md5(s) {
			return this.binl2rstr(this.binl_md5(this.rstr2binl(s), s.length * 8));
		}

		/*
		* Calculate the HMAC-MD5, of a key and some data (raw strings)
		*/
		private rstr_hmac_md5(key, data) {
			var i,
				bkey = this.rstr2binl(key),
				ipad = [],
				opad = [],
				hash;
			ipad[15] = opad[15] = undefined;
			if (bkey.length > 16) {
				bkey = this.binl_md5(bkey, key.length * 8);
			}
			for (i = 0; i < 16; i += 1) {
				ipad[i] = bkey[i] ^ 0x36363636;
				opad[i] = bkey[i] ^ 0x5C5C5C5C;
			}
			hash = this.binl_md5(ipad.concat(this.rstr2binl(data)), 512 + data.length * 8);
			return this.binl2rstr(this.binl_md5(opad.concat(hash), 512 + 128));
		}

		/*
		* Convert a raw string to a hex string
		*/
		private rstr2hex(input) {
			var hex_tab = '0123456789abcdef',
				output = '',
				x,
				i;
			for (i = 0; i < input.length; i += 1) {
				x = input.charCodeAt(i);
				output += hex_tab.charAt((x >>> 4) & 0x0F) +
				hex_tab.charAt(x & 0x0F);
			}
			return output;
		}

		/*
		* Encode a string as utf-8
		*/
		private str2rstr_utf8(input) {
			return decodeURI(encodeURIComponent(input)); // unescape not supported in typescript
		}

		/*
		* Take string arguments and return either raw or hex encoded strings
		*/
		private raw_md5(s) {
			return this.rstr_md5(this.str2rstr_utf8(s));
		}
		private hex_md5(s) {
			return this.rstr2hex(this.raw_md5(s));
		}
		private raw_hmac_md5(k, d) {
			return this.rstr_hmac_md5(this.str2rstr_utf8(k), this.str2rstr_utf8(d));
		}
		private hex_hmac_md5(k, d) {
			return this.rstr2hex(this.raw_hmac_md5(k, d));
		}

		md5(val: string, key?: string, raw: boolean = false) {
			if (!key) {
				if (!raw) {
					return this.hex_md5(val);
				}
				return this.raw_md5(val);
			}
			if (!raw) {
				return this.hex_hmac_md5(key, val);
			}
			return this.raw_hmac_md5(key, val);
		}
	}

	//#endregion
}



module shearnie.tools.html {

	/* fill combo list
	 * usage:

		var pets: shearnie.tools.html.comboData[] = [];
		pets.push({
			groupHeading: "Dogs",
			getItems: () => {
				var ret: shearnie.tools.html.comboItem[] = [];
				model.dogs.forEach((item) => {
					ret.push({ value: item.id, display: item.name });
				})
				return ret;
			}
		});
		pets.push({
			groupHeading: "Cats",
			getItems: () => {
				var ret: shearnie.tools.html.comboItem[] = [];
				model.cats.forEach((item) => {
					ret.push({ value: item.id, display: item.name });
				})
				return ret;
			}
		});

		shearnie.tools.html.fillCombo($("#pets-combo"), pets, "Select your pet");
	*/
	export interface comboData {
		groupHeading?: string;
		getItems?: () => comboItem[];
		items?: comboItem[];
	}

	export interface comboItem {
		value: any;
		display: string;
	}

	export function fillCombo(cbo: JQuery,
		items: comboData[],
		prompt?: string) {
		if (cbo == null) return;

		cbo.empty();

		if (prompt != null)
			cbo.append($('<option>' + prompt + '</option>').attr("value", '').attr("disabled", 'disabled').attr("selected", 'selected'));

		if (items == null) return;

		items.forEach((item) => {
			// group heading
			if (item.groupHeading != null) {
				cbo.append($('<option></option>').attr("value", '').attr("disabled", 'disabled'));
				cbo.append('<optgroup label="' + item.groupHeading + '">');
			}

			// try to get if not specified (or intended to be set in getItems)
			if (item.items == null) {
				var getItems: comboItem[] = null;
				try {
					getItems = item.getItems();
				} catch (ex) {
					// pass on if defined but failed
					if (ex.name != 'TypeError') throw ex;
				}
				if (getItems != null) item.items = getItems;
			}

			// now fill items
			if (item.items != null)
				item.items.forEach((i) => {
					cbo.append($('<option></option>').attr("value", i.value).text(i.display));
				});
		});
	}

	// trunc long strings...
	export function truncstr(value: string, length: number) {
		if (value.length > length)
			return value.substring(0, length) + '...';
		else
			return value;
	};
}
