# yarahttpproxy

HTTP-Proxy with Yara matching of full request/response.

## Usage

```
$ ./yarahttpproxy -h
Usage of ./yarahttpproxy:
  -d	debug flag
  -hl string
    	host to listen on (e.g. 127.0.0.1:8080) (default "0.0.0.0:8080")
  -hr string
    	host to forward requests to (e.g. http://localhost:8090)
  -rules string
    	folder with all the rules to use (default "rules/")
```

There are two types of rules: incoming rules (`in`) and outgoing rules (`out`).
Incoming rules are for matching requests and outgoing rules are for matching responses.
Rules are stored in a folder (e.g. see `rules/`) and are prefixed with `in` or `out` and have to end with `.yar`.


All Yara rules should be supported (use one file per rule see `https://github.com/hillu/go-yara/issues/75`), one additional feature was added:
if `drop = true` is provided in the `meta` tag (see example rules) the request/response will be dropped (if its not provided it will be dropped (e.g. default)).

See https://yara.readthedocs.io/en/stable/writingrules.html for more info.

## Dependencies

- Yara > 4.0.0
- github.com/hillu/go-yara