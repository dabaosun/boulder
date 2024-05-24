# Self-Service Frontend (SFE)
The SFE is a self-service portal for [Let's Encrypt](https://letsencrypt.org/)
Subscribers to perform various administrative actions on their accounts. At this
time, the following actions are available;

1. Unpausing paused accounts

The SFE is tangentially related to the WFE in that both processes provide an
interface to interact with Let's Encrypt via the public internet. For
simplicity, the SFE implements standard `http.HandlerFuncs` differing from the
WFE's use of `//web` to construct `WFEHandlerFunc` which match the
`http.HandlerFunc` interface.

## Interesting bits
### Development Choices
The SFE makes heavy use of [html/template](https://pkg.go.dev/html/template) to
provide a static site served from RAM via
[net/http](https://pkg.go.dev/net/http#FileServerFS) with
[embed.FS](https://pkg.go.dev/embed#hdr-File_Systems) saving the SFE from
performing kernel I/O calls for each request. This also provides a compile-time
guarantee that rendered pages will be available for consumption. An operator
will not have to worry about packaging web resources along as they will be
served directly from the compiled binary. It would be prudent to reverse-proxy
standard HTTP/HTTPS web traffic to the SFE rather than directly exposing the
SFE.

## Web UI Development
Static content lives in `./static`.
Dynamic content lives in both `./pages` and `./templates`.
