# ChangeLog

## 1.1.0 (TBD)
- introduce PHP >= 7.2 compatibilty by using `SodiumCompat` wrapper;
- only use crypto functionality from Sodium, use `paragonie/random_compat` and 
  `symfony/polyfill-php56` for random functions and `hash_equals`;
- fix issues found by [Psalm](https://getpsalm.org/) and 
  [phpstan](https://github.com/phpstan/phpstan)

## 1.0.0 (2017-07-06)
- initial release
