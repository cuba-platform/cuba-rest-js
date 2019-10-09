(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.cuba = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
var storage_1 = require("./storage");
var util_1 = require("./util");
__export(require("./model"));
__export(require("./storage"));
var apps = [];
/**
 * Initializes app.
 * @param {AppConfig} config
 * @returns {CubaApp}
 */
function initializeApp(config) {
    if (config === void 0) { config = {}; }
    if (getApp(config.name) != null) {
        throw new Error("Cuba app is already initialized");
    }
    var cubaApp = new CubaApp(config.name, config.apiUrl, config.restClientId, config.restClientSecret, config.defaultLocale, config.storage);
    apps.push(cubaApp);
    return cubaApp;
}
exports.initializeApp = initializeApp;
/**
 * Retrieve previously initialized app by name.
 * @param {string} appName
 * @returns {CubaApp | null}
 */
function getApp(appName) {
    var nameToSearch = appName == null ? "" : appName;
    for (var _i = 0, apps_1 = apps; _i < apps_1.length; _i++) {
        var app = apps_1[_i];
        if (app.name === nameToSearch) {
            return app;
        }
    }
    return null;
}
exports.getApp = getApp;
function removeApp(appName) {
    var app = getApp(appName);
    if (!app) {
        throw new Error('App is not found');
    }
    app.cleanup();
    apps.splice(apps.indexOf(app), 1);
}
exports.removeApp = removeApp;
var CubaApp = /** @class */ (function () {
    function CubaApp(name, apiUrl, restClientId, restClientSecret, defaultLocale, storage) {
        if (name === void 0) { name = ""; }
        if (apiUrl === void 0) { apiUrl = "/app/rest/"; }
        if (restClientId === void 0) { restClientId = "client"; }
        if (restClientSecret === void 0) { restClientSecret = "secret"; }
        if (defaultLocale === void 0) { defaultLocale = "en"; }
        if (storage === void 0) { storage = new storage_1.DefaultStorage(); }
        this.name = name;
        this.apiUrl = apiUrl;
        this.restClientId = restClientId;
        this.restClientSecret = restClientSecret;
        this.defaultLocale = defaultLocale;
        this.storage = storage;
        this.tokenExpiryListeners = [];
        this.messagesLoadingListeners = [];
        this.enumsLoadingListeners = [];
        this.localeChangeListeners = [];
    }
    Object.defineProperty(CubaApp.prototype, "restApiToken", {
        get: function () {
            return this.storage.getItem(this.name + "_" + CubaApp.REST_TOKEN_STORAGE_KEY);
        },
        set: function (token) {
            this.storage.setItem(this.name + "_" + CubaApp.REST_TOKEN_STORAGE_KEY, token);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(CubaApp.prototype, "locale", {
        get: function () {
            var storedLocale = this.storage.getItem(this.name + "_" + CubaApp.LOCALE_STORAGE_KEY);
            return storedLocale ? storedLocale : this.defaultLocale;
        },
        set: function (locale) {
            var _this = this;
            this.storage.setItem(this.name + "_" + CubaApp.LOCALE_STORAGE_KEY, locale);
            this.localeChangeListeners.forEach(function (l) { return l(_this.locale); });
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Logs in user and stores token in provided storage.
     * @param {string} login
     * @param {string} password
     * @param {LoginOptions} options You can use custom endpoints e.g. {tokenEndpoint:'ldap/token'}.
     * @returns {Promise<{access_token: string}>}
     */
    CubaApp.prototype.login = function (login, password, options) {
        var _this = this;
        if (login == null) {
            login = "";
        }
        if (password == null) {
            password = "";
        }
        var fetchOptions = {
            method: "POST",
            headers: this._getBasicAuthHeaders(),
            body: "grant_type=password&username=" + encodeURIComponent(login) + "&password=" + encodeURIComponent(password),
        };
        var endpoint = options && options.tokenEndpoint ? options.tokenEndpoint : 'oauth/token';
        var loginRes = fetch(this.apiUrl + "v2/" + endpoint, fetchOptions)
            .then(this.checkStatus)
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
            _this.restApiToken = data.access_token;
            return data;
        });
        return loginRes;
    };
    CubaApp.prototype.logout = function () {
        return this.revokeToken(this.restApiToken);
    };
    CubaApp.prototype.revokeToken = function (token) {
        var fetchOptions = {
            method: 'POST',
            headers: this._getBasicAuthHeaders(),
            body: 'token=' + encodeURIComponent(token),
        };
        this.clearAuthData();
        return fetch(this.apiUrl + 'v2/oauth/revoke', fetchOptions).then(this.checkStatus);
    };
    CubaApp.prototype.loadEntities = function (entityName, options, fetchOptions) {
        return this.fetch('GET', 'v2/entities/' + entityName, options, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.loadEntitiesWithCount = function (entityName, options, fetchOptions) {
        var count;
        var optionsWithCount = __assign({}, options, { returnCount: true });
        return this.fetch('GET', "v2/entities/" + entityName, optionsWithCount, __assign({ handleAs: 'raw' }, fetchOptions))
            .then(function (response) {
            count = parseInt(response.headers.get('X-Total-Count'), 10);
            return response.json();
        }).then(function (result) { return ({ result: result, count: count }); });
    };
    CubaApp.prototype.searchEntities = function (entityName, entityFilter, options, fetchOptions) {
        var data = __assign({}, options, { filter: entityFilter });
        return this.fetch('GET', 'v2/entities/' + entityName + '/search', data, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.searchEntitiesWithCount = function (entityName, entityFilter, options, fetchOptions) {
        var count;
        var optionsWithCount = __assign({}, options, { filter: entityFilter, returnCount: true });
        return this.fetch('GET', 'v2/entities/' + entityName + '/search', optionsWithCount, __assign({ handleAs: 'raw' }, fetchOptions)).then(function (response) {
            count = parseInt(response.headers.get('X-Total-Count'), 10);
            return response.json();
        }).then(function (result) { return ({ result: result, count: count }); });
    };
    CubaApp.prototype.loadEntity = function (entityName, id, options, fetchOptions) {
        return this.fetch('GET', 'v2/entities/' + entityName + '/' + id, options, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.deleteEntity = function (entityName, id, fetchOptions) {
        return this.fetch('DELETE', 'v2/entities/' + entityName + '/' + id, null, fetchOptions);
    };
    CubaApp.prototype.commitEntity = function (entityName, entity, fetchOptions) {
        if (entity.id) {
            return this.fetch('PUT', 'v2/entities/' + entityName + '/' + entity.id, JSON.stringify(entity), __assign({ handleAs: 'json' }, fetchOptions));
        }
        else {
            return this.fetch('POST', 'v2/entities/' + entityName, JSON.stringify(entity), __assign({ handleAs: 'json' }, fetchOptions));
        }
    };
    CubaApp.prototype.invokeService = function (serviceName, methodName, params, fetchOptions) {
        var serializedParams = params != null ? JSON.stringify(params) : null;
        return this.fetch('POST', 'v2/services/' + serviceName + '/' + methodName, serializedParams, fetchOptions);
    };
    CubaApp.prototype.query = function (entityName, queryName, params, fetchOptions) {
        return this.fetch('GET', 'v2/queries/' + entityName + '/' + queryName, params, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.queryWithCount = function (entityName, queryName, params, fetchOptions) {
        var count;
        var paramsWithCount = __assign({}, params, { returnCount: true });
        return this.fetch('GET', "v2/queries/" + entityName + "/" + queryName, paramsWithCount, __assign({ handleAs: 'raw' }, fetchOptions))
            .then(function (response) {
            count = parseInt(response.headers.get('X-Total-Count'), 10);
            return response.json();
        })
            .then(function (result) { return ({ result: result, count: count }); });
    };
    CubaApp.prototype.queryCount = function (entityName, queryName, params, fetchOptions) {
        return this.fetch('GET', 'v2/queries/' + entityName + '/' + queryName + '/count', params, fetchOptions);
    };
    CubaApp.prototype.loadMetadata = function (fetchOptions) {
        return this.fetch('GET', 'v2/metadata/entities', null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.loadEntityMetadata = function (entityName, fetchOptions) {
        return this.fetch('GET', 'v2/metadata/entities' + '/' + entityName, null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.loadEntityViews = function (entityName, fetchOptions) {
        return this.fetch('GET', 'v2/metadata/entities/' + entityName + '/views', null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.loadEntityView = function (entityName, viewName, fetchOptions) {
        return this.fetch('GET', 'v2/metadata/entities/' + entityName + '/views/' + viewName + '/', null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.loadEntitiesMessages = function (fetchOptions) {
        var _this = this;
        var fetchRes = this.fetch('GET', 'v2/messages/entities', null, __assign({ handleAs: 'json' }, fetchOptions));
        fetchRes.then(function (messages) {
            _this.messagesCache = messages;
            _this.messagesLoadingListeners.forEach(function (l) { return l(messages); });
        });
        return fetchRes;
    };
    CubaApp.prototype.loadEnums = function (fetchOptions) {
        var _this = this;
        var fetchRes = this.fetch('GET', 'v2/metadata/enums', null, __assign({ handleAs: 'json' }, fetchOptions));
        fetchRes.then(function (enums) {
            _this.enumsCache = enums;
            _this.enumsLoadingListeners.forEach(function (l) { return l(enums); });
        });
        return fetchRes;
    };
    CubaApp.prototype.getPermissions = function (fetchOptions) {
        return this.fetch('GET', 'v2/permissions', null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.getUserInfo = function (fetchOptions) {
        return this.fetch('GET', 'v2/userInfo', null, __assign({ handleAs: 'json' }, fetchOptions));
    };
    CubaApp.prototype.getFileUploadURL = function () {
        return this.apiUrl + 'v2/files';
    };
    CubaApp.prototype.getFile = function (id, fetchOptions) {
        return this.fetch('GET', 'v2/files/' + id, null, __assign({ handleAs: 'blob' }, fetchOptions));
    };
    CubaApp.prototype.fetch = function (method, path, data, fetchOptions) {
        var _this = this;
        var url = this.apiUrl + path;
        var settings = __assign({ method: method, headers: {
                "Accept-Language": this.locale,
            } }, fetchOptions);
        if (this.restApiToken) {
            settings.headers["Authorization"] = "Bearer " + this.restApiToken;
        }
        if (method === 'POST' || method === 'PUT') {
            settings.body = data;
            settings.headers["Content-Type"] = "application/json; charset=UTF-8";
        }
        if (method === 'GET' && data && Object.keys(data).length > 0) {
            url += '?' + util_1.encodeGetParams(data);
        }
        var handleAs = fetchOptions ? fetchOptions.handleAs : undefined;
        switch (handleAs) {
            case "text":
                settings.headers["Accept"] = "text/html";
                break;
            case "json":
                settings.headers["Accept"] = "application/json";
                break;
        }
        var fetchRes = fetch(url, settings).then(this.checkStatus);
        fetchRes.catch(function (error) {
            if (_this.isTokenExpiredResponse(error.response)) {
                _this.clearAuthData();
                _this.tokenExpiryListeners.forEach(function (l) { return l(); });
            }
        });
        return fetchRes.then(function (resp) {
            if (resp.status === 204) {
                return resp.text();
            }
            switch (handleAs) {
                case "text":
                    return resp.text();
                case "blob":
                    return resp.blob();
                case "json":
                    return resp.json();
                case "raw":
                    return resp;
                default:
                    return resp.text();
            }
        });
    };
    CubaApp.prototype.onLocaleChange = function (c) {
        var _this = this;
        this.localeChangeListeners.push(c);
        return function () { return _this.localeChangeListeners.splice(_this.localeChangeListeners.indexOf(c), 1); };
    };
    CubaApp.prototype.onTokenExpiry = function (c) {
        var _this = this;
        this.tokenExpiryListeners.push(c);
        return function () { return _this.tokenExpiryListeners.splice(_this.tokenExpiryListeners.indexOf(c), 1); };
    };
    CubaApp.prototype.onEnumsLoaded = function (c) {
        var _this = this;
        this.enumsLoadingListeners.push(c);
        return function () { return _this.enumsLoadingListeners.splice(_this.enumsLoadingListeners.indexOf(c), 1); };
    };
    CubaApp.prototype.onMessagesLoaded = function (c) {
        var _this = this;
        this.messagesLoadingListeners.push(c);
        return function () { return _this.messagesLoadingListeners.splice(_this.messagesLoadingListeners.indexOf(c), 1); };
    };
    CubaApp.prototype.cleanup = function () {
        this.storage.clear();
    };
    CubaApp.prototype.isTokenExpiredResponse = function (resp) {
        return resp && resp.status === 401;
        // && resp.responseJSON
        // && resp.responseJSON.error === 'invalid_token';
    };
    CubaApp.prototype._getBasicAuthHeaders = function () {
        return getBasicAuthHeaders(this.restClientId, this.restClientSecret, this.locale);
    };
    CubaApp.prototype.checkStatus = function (response) {
        if (response.status >= 200 && response.status < 300) {
            return response;
        }
        else {
            return Promise.reject({ message: response.statusText, response: response });
        }
    };
    CubaApp.prototype.clearAuthData = function () {
        this.storage.removeItem(this.name + "_" + CubaApp.REST_TOKEN_STORAGE_KEY);
        this.storage.removeItem(this.name + "_" + CubaApp.USER_NAME_STORAGE_KEY);
    };
    CubaApp.REST_TOKEN_STORAGE_KEY = "cubaAccessToken";
    CubaApp.USER_NAME_STORAGE_KEY = "cubaUserName";
    CubaApp.LOCALE_STORAGE_KEY = "cubaLocale";
    return CubaApp;
}());
exports.CubaApp = CubaApp;
function getBasicAuthHeaders(client, secret, locale) {
    if (locale === void 0) { locale = 'en'; }
    return {
        "Accept-Language": locale,
        "Authorization": "Basic " + util_1.base64encode(client + ':' + secret),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    };
}
exports.getBasicAuthHeaders = getBasicAuthHeaders;

},{"./model":2,"./storage":3,"./util":4}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var PredefinedView;
(function (PredefinedView) {
    PredefinedView["MINIMAL"] = "_minimal";
    PredefinedView["LOCAL"] = "_local";
    PredefinedView["BASE"] = "_base";
})(PredefinedView = exports.PredefinedView || (exports.PredefinedView = {}));

},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Simple im-memory storage compatible with localStorage/sessionStorage API.
 */
var DefaultStorage = /** @class */ (function () {
    function DefaultStorage() {
        this.items = {};
    }
    Object.defineProperty(DefaultStorage.prototype, "length", {
        get: function () {
            return Object.keys(this.items).length;
        },
        enumerable: true,
        configurable: true
    });
    DefaultStorage.prototype.clear = function () {
        this.items = {};
    };
    DefaultStorage.prototype.getItem = function (key) {
        return this.items[key];
    };
    /**
     * @deprecated operation not supported
     */
    DefaultStorage.prototype.key = function (index) {
        throw new Error('Unsupported operation');
    };
    DefaultStorage.prototype.removeItem = function (key) {
        delete this.items[key];
    };
    DefaultStorage.prototype.setItem = function (key, data) {
        this.items[key] = data;
    };
    return DefaultStorage;
}());
exports.DefaultStorage = DefaultStorage;

},{}],4:[function(require,module,exports){
(function (global){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function base64encode(str) {
    /* tslint:disable:no-string-literal */
    if (typeof btoa === 'function') {
        return btoa(str);
    }
    else if (global['Buffer']) { // prevent Buffer from being injected by browserify
        return new global['Buffer'](str).toString('base64');
    }
    else {
        throw new Error('Unable to encode to base64');
    }
    /* tslint:enable:no-string-literal */
}
exports.base64encode = base64encode;
function encodeGetParams(data) {
    return Object
        .keys(data)
        .map(function (key) {
        return encodeURIComponent(key) + "=" + (encodeURIComponent(serialize(data[key])));
    })
        .join("&");
}
exports.encodeGetParams = encodeGetParams;
function serialize(rawParam) {
    if (rawParam == null) {
        return '';
    }
    if (typeof rawParam === 'object') {
        return JSON.stringify(rawParam);
    }
    return rawParam;
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}]},{},[1])(1)
});
