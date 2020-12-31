# ACov

ACov is another [Frida-based][frida] code coverage collection tool. It outputs
coverage data in the ["Module+Offset"][lighthouse-modoff] format supported by
[Lighthouse][lighthouse].

## Installation

Ensure that you have NPM and [poetry][poetry] installed. Run the following
commands:

```
npm install
npm run build
poetry install --no-dev
```

See `acov --help` for usage information once the installation is completed.

[frida]: https://frida.re/
[poetry]: https://github.com/sdispater/poetry
[lighthouse]: https://github.com/gaasedelen/lighthouse
[lighthouse-modoff]: https://github.com/gaasedelen/lighthouse/tree/master/coverage#module--offset-modoff
