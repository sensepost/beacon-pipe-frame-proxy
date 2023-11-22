# beacon-pipe-frame-proxy

<img align="right" src="./images/logo.png" height="180" alt="beacon-pip-frame-proxy">

A toy, C# Cobalt Strike Beacon TCP to Named Pipe Frame Proxy.

This proxy is useful in situations where your external c2 client can't stay alive for a long period of time. When reconnecting to a beacon named pipe, the beacon would consider that new socket connection to be a new session, responding with an initial metadata frame.

To avoid this problem, the proxy will keep it's connection open to an upstream named pipe, while accepting new TCP connections. For any connected TCP client (and assuming the bytes being sent conform to the `[length][payload]` format from the Cobalt Strike [External C2 specification](https://hstechdocs.helpsystems.com/kbfiles/cobaltstrike/attachments/externalc2spec.pdf)), data will be passed to the connected named pipe and back to the TCP client.

## usage

Once built, run the proxy by specifying the local pipe name to connect to and the TCP port to listen on. Example:

```text
proxy.exe lightneuron 8888
```

Spawning this with a stealthier approach is an exercise left up to you.

## license

`beacon-pipe-frame-proxy` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at [http://sensepost.com/contact/](http://sensepost.com/contact/).
