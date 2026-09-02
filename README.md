# check_http2

Nagios check_http plugin alternative.
Not implemented full feature, only we need.

## Usage

```
Usage:
  check_http2 [OPTIONS]

Application Options:
      --timeout=                  Timeout to wait for connection (default: 10s)
      --max-buffer-size=          Max buffer size to read response body (default: 1MB)
      --no-discard                raise error when the response body is larger then max-buffer-size
      --consecutive=              number of consecutive successful requests required (default: 1)
      --interim=                  interval time after successful request for consecutive mode (default: 1s)
      --wait-for                  retry until successful when enabled
      --wait-for-interval=        retry interval (default: 2s)
      --wait-for-max=             time to wait for success
  -H, --hostname=                 Host name using Host headers
  -I, --IP-address=               IP address or Host name
  -p, --port=                     Port number
  -j, --method=                   Set HTTP Method (default: GET)
  -u, --uri=                      URI to request (default: /)
  -e, --expect=                   Comma-delimited list of expected HTTP response status (default: HTTP/1.,HTTP/2.)
  -s, --string=                   String to expect in the content
      --base64-string=            Base64 Encoded string to expect the content
  -A, --useragent=                UserAgent to be sent (default: check_http)
  -a, --authorization=            username:password on sites with basic
                                  authentication (visible in the process list;
                                  prefer authorization-file)
      --authorization-file=       file holding username:password, read instead
                                  of passing it on the command line
  -S, --ssl                       use https
      --sni                       require a hostname for SNI (SNI is always
                                  sent for a hostname)
      --tls-max=[1.0|1.1|1.2|1.3] maximum supported TLS version
  -4                              use tcp4 only
  -6                              use tcp6 only
      --verify-ssl                verify SSL certificate (the default; kept for
                                  compatibility)
  -k, --ignore-ssl-error          ignore SSL/TLS errors: skip certificate
                                  verification and allow legacy TLS versions,
                                  cipher suites and key exchanges
  -v, --version                   Show version

Help Options:
  -h, --help                      Show this help message
```

example

check with HEAD request

```
% ./check_http2 -S  -I blog.nomadscafe.jp -H blog.nomadscafe.jp -u /2016/03/retty-tech-cafe-5.html -e 'HTTP/1.0 200,HTTP/1.1 200,HTTP/2.0 200' -j HEAD --sni
HTTP OK: Status line output "HTTP/2.0 200 OK" matched "HTTP/2.0 200"  - 482 bytes in 0.349 second response time | time=0.349428s;;;0.000000 size=482B;;;0
```

ignore SSL/TLS errors

Certificates are verified by default, so an expired, self-signed or wrong-host
certificate makes the check fail. `--verify-ssl` is therefore a no-op, kept so
existing command lines keep working.

`-k` / `--ignore-ssl-error` waives that, and cannot be combined with
`--verify-ssl`. It also relaxes the handshake itself, which is what a
server-side `remote error: tls: handshake failure` needs: legacy TLS versions
(down to 1.0), every cipher suite this build implements, and only the classic key
exchanges, because the post-quantum key share sent by default makes some servers
and middleboxes abort the handshake. Both parts are insecure by intent — reach
for it when checking an endpoint whose TLS you knowingly cannot fix, not as a
habit.

```
% ./check_http2 -S -I 192.0.2.10 -H legacy.example.com --sni -k
HTTP OK: Status line output "HTTP/1.1 200 OK" matched "HTTP/1."  - 1234 bytes in 0.031 second response time | time=0.031000s;;;0.000000 size=1234B;;;0
```

basic authentication without exposing the credentials

`-a` puts the credentials in the process list, where any local user can read
them with `ps`, and they end up in the monitoring configuration and the shell
history. `--authorization-file` reads them from a file instead; the two cannot
be combined.

The file holds `username:password` on its first line and nothing else.
`/etc/nagios/check_http2.auth`:

```
monitor:s3cr3t
```

No key, no quotes, no comments: the first line is taken verbatim, so a leading
`#` would become part of the username. Only the line ending is stripped (`\n`
or `\r\n`), which means a password may contain spaces. Any further lines are
ignored.

Create it readable by the monitoring user alone, then point the check at it:

```
% install -m 600 /dev/null /etc/nagios/check_http2.auth
% printf 'monitor:s3cr3t\n' > /etc/nagios/check_http2.auth
% ./check_http2 -S -H example.com --authorization-file /etc/nagios/check_http2.auth
```

A missing file, an empty one, or a line without a colon fails the check with
UNKNOWN before any request is sent. Two things are pointed out on stderr
without failing the check: a file that is accessible to more than its owner,
and credentials sent over plain `http`, where they go out unencrypted.

## Notes

`--sni` does not switch SNI on: for a hostname it is always sent, so the flag
only enforces that a hostname is given. It is kept for compatibility.

Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) are ignored on
purpose. The plugin connects to the address given by `-I`/`-p`, so a proxy
could never be reached anyway.

The `Host` header carries the port whenever it is not the scheme default, as
`check_http` sends it: `-H example.com -p 8443 -S` requests
`Host: example.com:8443`.

`-e`/`--expect` entries are trimmed, so `-e 'HTTP/1.1 200, HTTP/2.0 200'`
works; empty entries are ignored rather than matching everything.

`--max-buffer-size` limits how much of the body is held in memory, not what is
searched: `-s`/`--base64-string` matches anywhere in the response, and
`--no-discard` still turns an oversized body into an error.

wait for success

```
% ./check_http2 -S -H blog.nomadscafe.jp -s kazeburo-wait-for --wait-for --wait-for-max 10s
2021/03/24 15:44:20 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:22 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:24 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:27 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
2021/03/24 15:44:29 HTTP CRITICAL - HTTP response body Not matched "kazeburo-wait-for" from host on port 443
Give up waiting for success
```

