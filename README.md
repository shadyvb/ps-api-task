## Setup and scripts

For convenience, you can use `composer setup:fresh` to setup the project, seed the database and run the migrations. Then `composer run dev` to start the development server.

`composer test` will run the tests, and `composer lint` will run the linter.

So this should do the trick:

```bash
composer setup:fresh
composer test
composer lint
composer run dev
```
