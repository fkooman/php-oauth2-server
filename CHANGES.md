# ChangeLog

## 2.0.0 (...)
- remove "implicit grant" support, only support "autorization code"
- fix some additional Psalm warnings
- introduce `ServerException`
- add support for PHPUnit 6
- introduce `TokenResponse` object to make integration in applications easier
- introduce `ApiResponse` and `AuthorizeResponse` as well

## 1.1.0 (2017-09-18)
- introduce PHP >= 7.2 compatibilty by using `SodiumCompat` wrapper;
- only use crypto functionality from Sodium, use polyfills for the rest;
- fix issues found by [Psalm](https://getpsalm.org/) and 
  [phpstan](https://github.com/phpstan/phpstan)

## 1.0.0 (2017-07-06)
- initial release
