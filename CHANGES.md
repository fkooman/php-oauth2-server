# ChangeLog

## 4.0.0 (...)
- remove `SodiumSigner`
- introduce simple `HmacSigner`
- drop multi key support
- remove Key ID support
- introduce `ClientDbInterface` and `ArrayClientDb` instead of crummy 
  `callable`

## 3.0.2 (2018-09-21)
- explicitly depend on versions of `paragonie/constant_time_encoding` that 
  support `Base64UrlSafe::encodeUnpadded`, drop hack
- simplify matching ports in redirect URI

## 3.0.1 (2018-06-08)
- use safe `strlen` and `substr` from `paragonie/constant_time_encoding`
- introduce `Util` class
- native function invocation (prefix all function calls with a `\`)
- support PHPUnit 7
- add `psalm.xml`
- relax `paragonie/random_compat` version requirement
- use `Base64UrlSafe::encodeUnpadded` if it is available

## 3.0.0 (2018-03-19)
- API changes
  - remove `OAuthServer::setExpiry`, `OAuthServer::setExpiresIn`
  - add `OAuthServer::setAccessTokenExpiry` and 
    `OAuthServer::setRefreshTokenExpiry`
  - `OAuthServer` constructor takes `SignerInterface` now instead of a string
    keypair, implementation available as `SodiumSigner`
  - add `SodiumSigner` which is compatible with previously issued access and 
    refresh tokens (from version ^2)
  - the `TokenInfo` object now has the `requireAnyScope` and `requireAllScope` 
    methods instead of `BearerValidator`
  - `SodiumSigner` takes the decoded keypair as parameter, no longer Base64 
    encoded
  - `SodiumSigner` takes decoded public keys as the second parameter to the 
    constructor, where the array key is the key ID
- introduce `RedirectResponse` for handling redirects;
- remove `HtmlResponse`
- change date format to `DateTime::ATOM` format in issued tokens
- no longer expire refresh tokens by default, requiring explicit call to
  `OAuthServer::setRefreshTokenExpiry` to make refresh tokens expire

## 2.2.0 (2018-01-10)
- all issued tokens are also "URL safe" now (without padding), Base64 encoded 
  tokens issued in previous versions are still valid
- introduce `OAuthServer::setExpiry` to allow specifying `DateInterval`
- deprecate `OAuthServer::setExpiresIn`
- allow specifying expiry for refresh tokens through `OAuthServer::setExpiry` 
  (issue #26)
  - new issued refresh tokens now **expire after 1 year** by default, old 
    issued refresh tokens will remain valid indefinitely or until user revokes
    the authorization

## 2.1.0 (2017-11-30)
- make it possible to disable requiring user approval for authorization of
  trusted clients

## 2.0.1 (2017-11-29)
- rework (lib)sodium compatibility
- encode the authorization code "URL safe" without padding
  - this fixes incompatibilities with Internet Explorer 11
  - this invalidates "in flight" authorization codes when a user is 
    authorizing at that particular moment. As codes are only valid for 5 
    minutes and the typical flow takes only a few seconds, this seems
    acceptable

## 2.0.0 (2017.11-14)
- remove "implicit grant" support, only support "authorization code"
- static code analysis fixes found by [Psalm](https://github.com/vimeo/psalm)
- rework Exception handling
- introduce Response objects
- support for PHPUnit 6
- do not accept tokens from deleted clients, API update (issue #14)
- `ClientInfo` now requires `redirect_uri_list`, MUST be `array`

## 1.1.0 (2017-09-18)
- introduce PHP >= 7.2 compatibility by using `SodiumCompat` wrapper;
- only use crypto functionality from Sodium, use polyfills for the rest;
- fix issues found by [Psalm](https://getpsalm.org/) and 
  [phpstan](https://github.com/phpstan/phpstan)

## 1.0.0 (2017-07-06)
- initial release
