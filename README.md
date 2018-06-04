# Introduction
This is a very simple OAuth 2.0 server for integration in your own application. 
It has minimal dependencies, but still tries to be secure. The main purpose is 
to be compatible with PHP 5.4.

**NOTE**: if you are not bound to PHP 5.4, use the OAuth 2.0 server of 
the League of Extraordinary Packages! It can be found 
[here](https://oauth2.thephpleague.com/).

# Client Support

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
- Supports (expiring) refresh tokens;
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

You can use [php-oauth2-client](https://git.tuxed.net/fkooman/php-oauth2-client/)
as a client to interact with this server, the example there is configured 
to work with this server.

# Generating a Keypair

The OAuth server uses public key cryptography to sign the access tokens it 
generates. In order to generate this keypair, you can use the commands shown 
below. This is also a good test to see if (lib)sodium works properly in your
PHP.

On older PHP versions with PECL libsodium version 1.x:

    $ php -r "file_put_contents('server.key', \Sodium\crypto_sign_keypair());"
    $ php -r "file_put_contents('server_public.key', \Sodium\crypto_sign_publickey(file_get_contents('server.key')));"

On PHP >= 7.2 or PECL libsodium version 2.x:

    $ php -r "file_put_contents('server.key', sodium_crypto_sign_keypair());"
    $ php -r "file_put_contents('server_public.key', sodium_crypto_sign_publickey(file_get_contents('server.key')));"

The data in `server.key` file can then be used as input to the `SodiumSigner` 
class, see the example. The `server_public.key` file will contain only the 
public component of the keypair.

# Accepting Additional Public Keys

The `BearerValidator` class can be configured to accept additional public keys 
in addition to the "local" one that is also used for signing authorization 
codes, refresh tokens and access tokens.

This can be configured by specifying a second parameter to the `SodiumSigner` 
constructor, using a mapping between key identifiers (key ID) and the 
(binary) public key. For example:

    $sodiumSigner = new SodiumSigner(
        file_get_contents('server_1.key'),  // local key
        [
            'server_2' => file_get_contents('server_2_public.key'), // remote key
            'server_3' => file_get_contents('server_3_public.key'), // remote key
        ]
    );

The `TokenInfo::getKeyId` method can be used to verify which public key was 
used to verify the Bearer token. If the local key was used, this call will 
return `local`, otherwise the Key ID as configured. Here that would be either 
`server_2` or `server_3`.

# Contact

You can contact me with any questions or issues regarding this project. Drop
me a line at [fkooman@tuxed.net](mailto:fkooman@tuxed.net).

If you want to (responsibly) disclose a security issue you can also use the
PGP key with key ID `9C5EDD645A571EB2` and fingerprint
`6237 BAF1 418A 907D AA98  EAA7 9C5E DD64 5A57 1EB2`.

# License

[MIT](LICENSE).
