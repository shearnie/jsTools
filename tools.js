﻿var shearnie;
(function (shearnie) {
    (function (tools) {
        var PostData = (function () {
            function PostData(url, data) {
                this.url = url;
                this.data = data;

                this.hashid = new Md5().md5(url);
            }
            return PostData;
        })();
        tools.PostData = PostData;

        var Poster = (function () {
            function Poster() {
            }
            Poster.prototype.SendSync = function (url, data) {
                if (url == null || url == '')
                    throw 'No target.';

                var obj = null;
                var error = null;

                var setobj = function (result) {
                    obj = result;
                };

                var seterr = function (err) {
                    error = err;
                };

                $.when($.ajax({
                    type: 'POST',
                    url: url,
                    data: data,
                    dataType: "json",
                    async: false
                })).then(function (result) {
                    setobj(result);
                }, function (err) {
                    seterr(err);
                });

                if (error != null)
                    throw error;
                return obj;
            };

            Poster.prototype.SendAsync = function (postData, onCompleted) {
                var _this = this;
                if (postData == null)
                    throw 'No target/s.';
                if (postData.length == 0)
                    throw 'No target/s.';

                var errCount = 0;
                postData.forEach(function (pd) {
                    pd.result = null;
                    pd.error = null;
                    $.when($.ajax({
                        type: 'POST',
                        url: pd.url,
                        data: pd.data,
                        dataType: "json",
                        async: true
                    })).then(function (result) {
                        pd.result = result;
                        if (!_this.checkAnyEmpty(postData))
                            onCompleted(errCount);
                    }, function (err) {
                        pd.error = err;
                        errCount++;
                        if (!_this.checkAnyEmpty(postData))
                            onCompleted(errCount);
                    });
                });
            };

            Poster.prototype.checkAnyEmpty = function (postData) {
                var ret = false;
                postData.every(function (pd) {
                    if (pd.result == null)
                        if (pd.error == null) {
                            ret = true;
                            return false;
                        }
                    return true;
                });
                return ret;
            };

            Poster.prototype.findPostData = function (postData, hashToMatch) {
                var ret = null;
                postData.every(function (pd) {
                    if (pd.hashid == hashToMatch) {
                        ret = pd;
                        return false;
                    }
                    return true;
                });
                return ret;
            };
            return Poster;
        })();
        tools.Poster = Poster;

        var Md5 = (function () {
            function Md5() {
            }
            Md5.prototype.safe_add = function (x, y) {
                var lsw = (x & 0xFFFF) + (y & 0xFFFF), msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                return (msw << 16) | (lsw & 0xFFFF);
            };

            Md5.prototype.bit_rol = function (num, cnt) {
                return (num << cnt) | (num >>> (32 - cnt));
            };

            Md5.prototype.md5_cmn = function (q, a, b, x, s, t) {
                return this.safe_add(this.bit_rol(this.safe_add(this.safe_add(a, q), this.safe_add(x, t)), s), b);
            };
            Md5.prototype.md5_ff = function (a, b, c, d, x, s, t) {
                return this.md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
            };
            Md5.prototype.md5_gg = function (a, b, c, d, x, s, t) {
                return this.md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
            };
            Md5.prototype.md5_hh = function (a, b, c, d, x, s, t) {
                return this.md5_cmn(b ^ c ^ d, a, b, x, s, t);
            };
            Md5.prototype.md5_ii = function (a, b, c, d, x, s, t) {
                return this.md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
            };

            Md5.prototype.binl_md5 = function (x, len) {
                x[len >> 5] |= 0x80 << ((len) % 32);
                x[(((len + 64) >>> 9) << 4) + 14] = len;

                var i, olda, oldb, oldc, oldd, a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;

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
            };

            Md5.prototype.binl2rstr = function (input) {
                var i, output = '';
                for (i = 0; i < input.length * 32; i += 8) {
                    output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
                }
                return output;
            };

            Md5.prototype.rstr2binl = function (input) {
                var i, output = [];
                output[(input.length >> 2) - 1] = undefined;
                for (i = 0; i < output.length; i += 1) {
                    output[i] = 0;
                }
                for (i = 0; i < input.length * 8; i += 8) {
                    output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
                }
                return output;
            };

            Md5.prototype.rstr_md5 = function (s) {
                return this.binl2rstr(this.binl_md5(this.rstr2binl(s), s.length * 8));
            };

            Md5.prototype.rstr_hmac_md5 = function (key, data) {
                var i, bkey = this.rstr2binl(key), ipad = [], opad = [], hash;
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
            };

            Md5.prototype.rstr2hex = function (input) {
                var hex_tab = '0123456789abcdef', output = '', x, i;
                for (i = 0; i < input.length; i += 1) {
                    x = input.charCodeAt(i);
                    output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
                }
                return output;
            };

            Md5.prototype.str2rstr_utf8 = function (input) {
                return decodeURI(encodeURIComponent(input));
            };

            Md5.prototype.raw_md5 = function (s) {
                return this.rstr_md5(this.str2rstr_utf8(s));
            };
            Md5.prototype.hex_md5 = function (s) {
                return this.rstr2hex(this.raw_md5(s));
            };
            Md5.prototype.raw_hmac_md5 = function (k, d) {
                return this.rstr_hmac_md5(this.str2rstr_utf8(k), this.str2rstr_utf8(d));
            };
            Md5.prototype.hex_hmac_md5 = function (k, d) {
                return this.rstr2hex(this.raw_hmac_md5(k, d));
            };

            Md5.prototype.md5 = function (val, key, raw) {
                if (typeof raw === "undefined") { raw = false; }
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
            };
            return Md5;
        })();
        tools.Md5 = Md5;
    })(shearnie.tools || (shearnie.tools = {}));
    var tools = shearnie.tools;
})(shearnie || (shearnie = {}));

var shearnie;
(function (shearnie) {
    (function (tools) {
        (function (html) {
            

            function fillCombo(cbo, items, prompt) {
                if (cbo == null)
                    return;

                cbo.empty();

                if (prompt != null)
                    cbo.append($('<option>' + prompt + '</option>').attr("value", '').attr("disabled", 'disabled').attr("selected", 'selected'));

                if (items == null)
                    return;

                items.forEach(function (item) {
                    if (item.groupHeading != null) {
                        cbo.append($('<option></option>').attr("value", '').attr("disabled", 'disabled'));
                        cbo.append('<optgroup label="' + item.groupHeading + '">');
                    }

                    if (item.items == null) {
                        var getItems = null;
                        try  {
                            getItems = item.getItems();
                        } catch (ex) {
                            if (ex.name != 'TypeError')
                                throw ex;
                        }
                        if (getItems != null)
                            item.items = getItems;
                    }

                    if (item.items != null)
                        item.items.forEach(function (i) {
                            cbo.append($('<option></option>').attr("value", i.value).text(i.display));
                        });
                });
            }
            html.fillCombo = fillCombo;

            function truncstr(value, length) {
                if (value.length > length)
                    return value.substring(0, length) + '...';
                else
                    return value;
            }
            html.truncstr = truncstr;
            ;
        })(tools.html || (tools.html = {}));
        var html = tools.html;
    })(shearnie.tools || (shearnie.tools = {}));
    var tools = shearnie.tools;
})(shearnie || (shearnie = {}));
//# sourceMappingURL=tools.js.map
