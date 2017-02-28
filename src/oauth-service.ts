import { Base64 } from 'js-base64';
import { fromByteArray } from 'base64-js';
import * as _sha256 from 'sha256';
import { Http, URLSearchParams, Headers } from '@angular/http';
import { Injectable } from '@angular/core';
import { Observable, Observer } from 'rxjs';

const sha256: any = _sha256;

@Injectable()
export class OAuthService {

    public clientId = '';
    public redirectUri = '';
    public loginUrl = '';
    public scope = '';
    public resource = '';
    public rngUrl = '';
    public oidc = false;
    public hybrid = false;
    public options: any;
    public state = '';
    public issuer = '';
    public validationHandler: any;
    public logoutUrl = '';
    public clearHashAfterLogin: boolean = true;
    public tokenEndpoint: string;
    public userinfoEndpoint: string;

    public dummyClientSecret: string;

    public discoveryDocumentLoaded: boolean = false;
    public discoveryDocumentLoaded$: Observable<any>;
    private discoveryDocumentLoadedSender: Observer<any>;

    private grantTypesSupported: Array<string> = [];

    private _storage: Storage = localStorage;

    public setStorage(storage: Storage) {
        this._storage = storage;
    }

    constructor(private http: Http) {
        this.discoveryDocumentLoaded$ = Observable.create(sender => {
            this.discoveryDocumentLoadedSender = sender;
        }).publish().connect();
    }

    loadDiscoveryDocument(fullUrl: string = null): Promise<any> {

        return new Promise((resolve, reject) => {

            if (!fullUrl) {
                fullUrl = this.issuer + '/.well-known/openid-configuration';
            }

            this.http.get(fullUrl).map(r => r.json()).subscribe(
                (doc) => {

                    this.loginUrl = doc.authorization_endpoint;
                    this.logoutUrl = doc.end_session_endpoint;
                    this.grantTypesSupported = doc.grant_types_supported;
                    this.issuer = doc.issuer;
                    // this.jwks_uri = this.jwks_uri;
                    this.tokenEndpoint = doc.token_endpoint;
                    this.userinfoEndpoint = doc.userinfo_endpoint;

                    this.discoveryDocumentLoaded = true;
                    this.discoveryDocumentLoadedSender.next(doc);
                    resolve(doc);
                },
                (err) => {
                    console.error('error loading dicovery document', err);
                    reject(err);
                }
            );
        });

    }

    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName: string, password: string) {
        return this
            .fetchTokenUsingPasswordFlow(userName, password)
            .then(() => this.loadUserProfile());
    }

    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw Error('Can not load User Profile without access_token');
        }

        return new Promise((resolve, reject) => {

            let headers = new Headers();
            headers.set('Authorization', 'Bearer ' + this.getAccessToken());

            this.http.get(this.userinfoEndpoint, { headers }).map(r => r.json()).subscribe(
                (doc) => {
                    this._storage.setItem('id_token_claims_obj', JSON.stringify(doc));
                    resolve(doc);
                },
                (err) => {
                    console.error('error loading user info', err);
                    reject(err);
                }
            );
        });


    }

    fetchTokenUsingPasswordFlow(userName: string, password: string) {

        return new Promise((resolve, reject) => {
            let search = new URLSearchParams();
            search.set('grant_type', 'password');
            search.set('client_id', this.clientId);
            search.set('scope', this.scope);
            search.set('username', userName);
            search.set('password', password);

            if (this.dummyClientSecret) {
                search.set('client_secret', this.dummyClientSecret);
            }

            let headers = new Headers();
            headers.set('Content-Type', 'application/x-www-form-urlencoded');

            let params = search.toString();

            this.http.post(this.tokenEndpoint, params, { headers }).map(r => r.json()).subscribe(
                (tokenResponse) => {
                    this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in);

                    resolve(tokenResponse);
                },
                (err) => {
                    console.error('Error performing password flow', err);
                    reject(err);
                }
            );
        });

    }

    fetchTokenUsingCode(code: string) {

        return new Promise((resolve, reject) => {
            let search = new URLSearchParams();
            search.set('grant_type', 'authorization_code');
            search.set('client_id', this.clientId);
            search.set('redirect_uri', this.redirectUri);
            search.set('code', code);

            if (this.dummyClientSecret) {
                search.set('client_secret', this.dummyClientSecret);
            }

            let headers = new Headers();
            headers.set('Content-Type', 'application/x-www-form-urlencoded');

            let params = search.toString();

            this.http.post(this.tokenEndpoint, params, { headers }).map(r => r.json()).subscribe(
                (tokenResponse) => {
                    this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in);

                    resolve(tokenResponse);
                },
                (err) => {
                    console.error('Error performing code flow', err);
                    reject(err);
                }
            );
        });

    }


    refreshToken() {

        const refreshToken = this._storage.getItem('refresh_token');
        if (refreshToken) {
            return new Promise((resolve, reject) => {
                let search = new URLSearchParams();
                search.set('grant_type', 'refresh_token');
                search.set('client_id', this.clientId);
                search.set('scope', this.scope);
                search.set('refresh_token', refreshToken);

                if (this.dummyClientSecret) {
                    search.set('client_secret', this.dummyClientSecret);
                }

                let headers = new Headers();
                headers.set('Content-Type', 'application/x-www-form-urlencoded');

                let params = search.toString();

                this.http.post(this.tokenEndpoint, params, { headers }).map(r => r.json()).subscribe(
                    (tokenResponse) => {
                        this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in);
                        resolve(tokenResponse);
                    },
                    (err) => {
                        console.error('Error performing password flow', err);
                        reject(err);
                    }
                );
            });
        }

    }


    createLoginUrl(state) {
        if (typeof state === 'undefined') { state = ''; }

        return this.createAndSaveNonce().then((nonce: any) => {

            if (state) {
                state = nonce + ';' + state;
            } else {
                state = nonce;
            }

            let response_type = 'token';

            if (this.oidc) {
                response_type = 'id_token ' + response_type;
            }

            if (this.hybrid) {
                response_type = 'code ' + response_type;
            }


            let url = this.loginUrl;

            if (/\?/.test(url)) {
                url += '&';
            } else {
                url += '?';
            }
            url += 'response_type='
                + response_type
                + '&client_id='
                + encodeURIComponent(this.clientId)
                + '&state='
                + encodeURIComponent(state)
                + '&redirect_uri='
                + encodeURIComponent(this.redirectUri)
                + '&scope='
                + encodeURIComponent(this.scope);

            if (this.resource) {
                url += '&resource=' + encodeURIComponent(this.resource);
            }

            if (this.oidc) {
                url += '&nonce=' + encodeURIComponent(nonce);
            }

            return url;
        });
    };

    initImplicitFlow(additionalState = '') {
        this.createLoginUrl(additionalState).then(function (url) {
            location.href = url;
        })
            .catch(function (error) {
                console.error('Error in initImplicitFlow');
                console.error(error);
            });
    };

    callEventIfExists(options: any) {
        if (options.onTokenReceived) {
            const tokenParams = {
                idClaims: this.getIdentityClaims(),
                idToken: this.getIdToken(),
                accessToken: this.getAccessToken(),
                state: this.state
            };
            options.onTokenReceived(tokenParams);
        }
    }

    private storeAccessTokenResponse(accessToken: string, refreshToken: string, expiresIn: number) {
        this._storage.setItem('access_token', accessToken);

        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }

        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
    }

    tryLogin(options?) {

        options = options || {};

        interface QueryStringParts {
            access_token: string;
            id_token: string;
            state: string;
            code: string;
        };

        const parts = this.getFragment() as QueryStringParts;
        const {access_token, id_token, state, code} = parts;

        let oidcSuccess = false;
        let oauthSuccess = false;

        if (!access_token || !state) {
            return false;
        }
        if (this.oidc && !id_token) {
            return false;
        }

        const savedNonce = this._storage.getItem('nonce');

        const stateParts = state.split(';');
        const nonceInState = stateParts[0];
        if (savedNonce === nonceInState) {

            this.storeAccessTokenResponse(access_token, null, parts['expires_in']);

            if (stateParts.length > 1) {
                this.state = stateParts[1];
            }

            oauthSuccess = true;

        }

        if (!oauthSuccess) {
            return false;
        }

        if (this.oidc) {
            oidcSuccess = this.processIdToken(id_token, access_token, code);
            if (!oidcSuccess) {
                return false;
            }
        }

        if (this.hybrid && code) {
            this.fetchTokenUsingCode(code);
        }

        if (options.validationHandler) {

            const validationParams = { accessToken: access_token, idToken: id_token };

            options
                .validationHandler(validationParams)
                .then(() => {
                    this.callEventIfExists(options);
                })
                .catch(function (reason) {
                    console.error('Error validating tokens');
                    console.error(reason);
                });
        } else {
            this.callEventIfExists(options);
        }

        // NEXT VERSION: Notify parent-window (iframe-refresh)
        /*
        var win = window;
        if (win.parent && win.parent.onOAuthCallback) {
            win.parent.onOAuthCallback(this.state);
        }
        */

        if (this.clearHashAfterLogin) {
            location.hash = '';
        }

        return true;
    };

    processIdToken(idToken, accessToken, code) {
        const tokenParts = idToken.split('.');
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = Base64.decode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        const savedNonce = this._storage.getItem('nonce');

        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                console.warn('Wrong audience: ' + claims.aud.join(','));
                return false;
            }
        } else {
            if (claims.aud !== this.clientId) {
                console.warn('Wrong audience: ' + claims.aud);
                return false;
            }
        }

        if (this.issuer && claims.iss !== this.issuer) {
            console.warn('Wrong issuer: ' + claims.iss);
            return false;
        }

        if (claims.nonce !== savedNonce) {
            console.warn('Wrong nonce: ' + claims.nonce);
            return false;
        }

        if (accessToken && !this.checkAtHash(accessToken, claims)) {
            console.warn('Wrong at_hash');
            return false;
        }

        if (code && !this.checkCHash(code, claims)) {
            console.warn('Wrong c_hash');
            return false;
        }

        // Das Prüfen des Zertifikates wird der Serverseite überlassen!

        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;

        const tenMinutesInMsec = 1000 * 60 * 10;

        if (issuedAtMSec - tenMinutesInMsec >= now || expiresAtMSec + tenMinutesInMsec <= now) {
            console.warn('Token has been expired');
            console.warn({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return false;
        }

        this._storage.setItem('id_token', idToken);
        this._storage.setItem('id_token_claims_obj', claimsJson);
        this._storage.setItem('id_token_expires_at', '' + expiresAtMSec);

        if (this.validationHandler) {
            this.validationHandler(idToken);
        }

        return true;
    }

    getIdentityClaims() {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }

    getIdToken() {
        return this._storage.getItem('id_token');
    }

    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }

    tryLoginWithIFrame() {
        throw new Error('tryLoginWithIFrame has not been implemented so far');
    };

    tryRefresh(timeoutInMsec) {
        throw new Error('tryRefresh has not been implemented so far');
    };

    getAccessToken() {
        return this._storage.getItem('access_token');
    };

    hasValidAccessToken() {
        if (this.getAccessToken()) {

            const expiresAt = this._storage.getItem('expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    };

    hasValidIdToken() {
        if (this.getIdToken()) {

            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }

            return true;
        }

        return false;
    };

    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }

    logOut(noRedirectToLogoutUrl = false) {
        const id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        this._storage.removeItem('nonce');
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');

        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }

        let logoutUrl: string;

        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl.replace(/\{\{id_token\}\}/, id_token);
        } else {
            logoutUrl = this.logoutUrl + '?id_token_hint='
                + encodeURIComponent(id_token)
                + '&post_logout_redirect_uri='
                + encodeURIComponent(this.redirectUri);
        }
        location.href = logoutUrl;
    };

    createAndSaveNonce() {
        return this.createNonce().then((nonce: any) => {
            this._storage.setItem('nonce', nonce);
            return nonce;
        });
    };

    createNonce() {

        return new Promise((resolve, reject) => {

            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            } else {
                let text = '';
                const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

                for (let i = 0; i < 64; i++) {
                    text += possible.charAt(Math.floor(Math.random() * possible.length));
                }

                resolve(text);
            }

        });
    };

    getFragment() {
        if (window.location.hash.indexOf('#') === 0) {
            return this.parseQueryString(window.location.hash.substr(1));
        } else {
            return {};
        }
    };

    parseQueryString(queryString) {
        let data = {}, pairs, pair, separatorIndex, escapedKey, escapedValue, key, value;

        if (queryString === null) {
            return data;
        }

        pairs = queryString.split('&');

        for (let i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');

            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            } else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }

            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);

            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }

            data[key] = value;
        }

        return data;
    };

    checkAtHash(accessToken, idClaims) {
        if (!accessToken || !idClaims || !idClaims.at_hash) {
            return true;
        }
        const tokenHash: Array<any> = sha256(accessToken, { asBytes: true });
        const leftMostHalf = tokenHash.slice(0, (tokenHash.length / 2));
        const tokenHashBase64 = fromByteArray(leftMostHalf);
        const atHash = tokenHashBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const claimsAtHash = idClaims.at_hash.replace(/=/g, '');

        if (atHash !== claimsAtHash) {
            console.warn('exptected at_hash: ' + atHash);
            console.warn('actual at_hash: ' + claimsAtHash);
        }


        return (atHash === claimsAtHash);
    }

    checkCHash(code, idClaims) {
        if (!code || !idClaims || !idClaims.c_hash) {
            return true;
        }
        const codeHash: Array<any> = sha256(code, { asBytes: true });
        const leftMostHalf = codeHash.slice(0, (codeHash.length / 2));
        const codeHashBase64 = fromByteArray(leftMostHalf);
        const cHash = codeHashBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const claimsCHash = idClaims.c_hash.replace(/=/g, '');

        if (cHash !== claimsCHash) {
            console.warn('exptected c_hash: ' + cHash);
            console.warn('actual c_hash: ' + claimsCHash);
        }


        return (cHash === claimsCHash);
    };

}
