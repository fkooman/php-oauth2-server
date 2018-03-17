# Introduction
This is a very simple OAuth 2.0 server for integration in your own application. 
It has minimal dependencies, but still tries to be secure. The main purpose is 
to be compatible with PHP 5.4.

**NOTE**: if you are not bound to PHP 5.4, use the OAuth 2.0 server of 
the League of Extraordinary Packages! It can be found 
[here](https://oauth2.thephpleague.com/).

# Clients

All (optional) OAuth authorization and token request parameters MUST always be
sent.

# Features

- Supports PHP >= 5.4;
- Simple;
- Only supports _Authorization Code Grant_;
- Easy integration with your own application and/or framework;
- Does not force a framework on you;
- There will be no toggles to shoot yourself in the foot;
- Supports [PKCE](https://tools.ietf.org/html/rfc7636);
- Supports refresh tokens;
- Do NOT implement RFC 6749 (#4.1.2.1) error response (except for 
  `access_denied`);

# Requirements

This library uses libsodium, either the PECL 
[module](https://github.com/jedisct1/libsodium-php), `php-libsodium` or the 
native Sodium module in PHP >= 7.2, `php-sodium`. You MUST have one of them 
installed in order to use this library, even though `composer.json` mentions
both of them as `suggest`.

# Using

See the `example/` directory.

You can start the OAuth server on your (development) machine using PHP's built
in web server:

    $ php -S localhost:8080 -t example/

If you have an OAuth client you can point it to 
`http://localhost:8080/authorize.php`.

You can use [php-oauth2-client](https://github.com/fkooman/php-oauth2-client/) 
as a client to interact with this server, the example there is configured 
to work with this server.

# Generating a Keypair

The OAuth server uses public key cryptography to sign the access tokens it 
generates. In order to generate this keypair, you can use the commands shown 
below. This is also a good test to see if (lib)sodium works properly in your
PHP.

On older PHP versions with PECL libsodium version 1.x:

    $ php -r "file_put_contents('server.key', \Sodium\crypto_sign_keypair());"

On PHP >= 7.2 or PECL libsodium version 2.x:

    $ php -r "file_put_contents('server.key', sodium_crypto_sign_keypair());"

The data in `server.key` file can then be used as input to the `SodiumSigner` 
class, see the example.

# License

[MIT](LICENSE).
