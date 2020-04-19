# Introduction

The project provides an opinionated OAuth 2.0 server library for integration in 
your own application. It has minimal dependencies, but still tries to be 
secure. The main purpose is to be as simple as possible whilst being secure.

This library supports all versions of PHP >= 5.4.

# Client Support

All (optional) OAuth authorization and token request parameters MUST always be
sent. PKCE is required for all client types.

# Features

- Supports PHP >= 5.4;
- Easy integration with your own application and/or framework;
- Does not require the use of a framework;
- Does NOT implement RFC 6749 (#4.1.2.1) error responses (except for 
  `access_denied`);
- Follows draft 
  [OAuth 2.1](https://tools.ietf.org/html/draft-parecki-oauth-v2-1-01) 
  recommendations:
  - Always requires [PKCE](https://tools.ietf.org/html/rfc7636);
  - Exact string match for `redirect_uri`;
  - Only supports _Authorization Code Grant_;
  - Refresh token rotation

# Requirements

On modern versions of PHP, i.e. >= 7, the library only requires 
`paragonie/constant_time_encoding`. On older versions it uses a couple of 
"polyfills", see `composer.json`.

# Use

Currently php-oauth2-server is not hosted on 
[Packagist](https://packagist.org/). It may be added in the future. In your 
`composer.json`:

    "repositories": [
        {
            "type": "vcs",
            "url": "https://git.tuxed.net/fkooman/php-oauth2-server"
        },
        ...
    ],

    "require": {
        "fkooman/oauth2-server": "^6",
        ...
    },

You can also download the signed source code archive 
[here](https://software.tuxed.net/php-oauth2-server/download.html).

# API

A simple, but complete example is included in the `example/` directory. The 
`authorize.php` script is the "authorize endpoint", the `token.php` script is
the "token endpoint" and the `api.php` script is the "protected resource" 
endpoint.

A demo key is included as `example/server.key`. For your own application you
MUST generate your own 32 bytes random key. This key is used to sign the
OAuth authorization codes, access tokens and refresh tokens instead of storing
them in the database.

In order to generate your own secret key, you can use the following command:

	$ dd if=/dev/urandom count=32 bs=1 | base64 | tr -d '=' | tr '/+' '_-'

Store this in a configuration file, or as a file on the disk.

You can start the demo OAuth server on your (development) machine using PHP's 
built in web server:

    $ php -S localhost:8080 -t example/

If you have an OAuth client you can point it to 
`http://localhost:8080/authorize.php`.

You can use 
[php-oauth2-client](https://git.tuxed.net/fkooman/php-oauth2-client/) as a 
client to interact with this server, the example there is configured to work 
with this server out of the box.

# Contact

You can contact me with any questions or issues regarding this project. Drop
me a line at [fkooman@tuxed.net](mailto:fkooman@tuxed.net).

If you want to (responsibly) disclose a security issue you can also use the
PGP key with key ID `9C5EDD645A571EB2` and fingerprint
`6237 BAF1 418A 907D AA98  EAA7 9C5E DD64 5A57 1EB2`.

# License

[MIT](LICENSE).
