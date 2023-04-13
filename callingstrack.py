#mitmproxy/addons/next_layer.py
def _next_layer(
    self, context: Context, data_client: bytes, data_server: bytes
) -> Layer | None:
    assert context.layers

    # 3)  Handle security protocols
    # 3a) TLS/DTLS
    is_tls_or_dtls = (
        tcp_based
        and starts_like_tls_record(data_client)
        or udp_based
        and starts_like_dtls_record(data_client)
    )
    if is_tls_or_dtls:
        server_tls = ServerTLSLayer(context)
        server_tls.child_layer = ClientTLSLayer(context)
        return server_tls
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/net/tls.py
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/proxy/layers/tls.py
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/proxy/server.py
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/contrib/kaitaistruct/tls_client_hello.py
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/tls.py

### /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/master.py

# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/addons/tlsconfig.py
# setup certificate
def configure(self, updated):
    if "confdir" not in updated and "certs" not in updated:
        return

    certstore_path = os.path.expanduser(ctx.options.confdir)
    self.certstore = certs.CertStore.from_store(
        path=certstore_path,
        basename=CONF_BASENAME,
        key_size=ctx.options.key_size,
        passphrase=ctx.options.cert_passphrase.encode("utf8")
        if ctx.options.cert_passphrase
        else None,
    )