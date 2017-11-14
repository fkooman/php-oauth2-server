# ChangeLog

## 2.0.0 (...)
- remove "implicit grant" support, only support "autorization code"
- static code analysis fixes found by [Psalm](https://github.com/vimeo/psalm)
- rework Exception handling
- introduce Response objects
- support for PHPUnit 6
- do not accept tokens from deleted clients, API update (issue #14)
- `ClientInfo` now requires `redirect_uri_list`, MUST be `array`

## 1.1.0 (2017-09-18)
- introduce PHP >= 7.2 compatibilty by using `SodiumCompat` wrapper;
- only use crypto functionality from Sodium, use polyfills for the rest;
- fix issues found by [Psalm](https://getpsalm.org/) and 
  [phpstan](https://github.com/phpstan/phpstan)

## 1.0.0 (2017-07-06)
- initial release
