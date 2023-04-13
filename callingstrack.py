
############## !!!!!    [KEY]     !!!!! ############## 
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

# !!!!!! start tls connection client & server 
def tls_start_client(self, tls_start: tls.TlsData) -> None:
    """Establish TLS or DTLS between client and proxy."""
    ssl_ctx = net_tls.create_client_proxy_context(
        method=net_tls.Method.DTLS_SERVER_METHOD
        if tls_start.is_dtls
        else net_tls.Method.TLS_SERVER_METHOD,
        min_version=net_tls.Version[ctx.options.tls_version_client_min],
        max_version=net_tls.Version[ctx.options.tls_version_client_max],
        cipher_list=tuple(cipher_list),
        chain_file=entry.chain_file,
        request_client_cert=False,
        alpn_select_callback=alpn_select_callback,
        extra_chain_certs=tuple(extra_chain_certs),
        dhparams=self.certstore.dhparams,
    )
    tls_start.ssl_conn = SSL.Connection(ssl_ctx)

    tls_start.ssl_conn.use_certificate(entry.cert.to_pyopenssl())
    tls_start.ssl_conn.use_privatekey(
        crypto.PKey.from_cryptography_key(entry.privatekey)
    )

def tls_start_server(self, tls_start: tls.TlsData) -> None:
    """Establish TLS or DTLS between proxy and server."""        
    ssl_ctx = net_tls.create_proxy_server_context(
        method=net_tls.Method.DTLS_CLIENT_METHOD
        if tls_start.is_dtls
        else net_tls.Method.TLS_CLIENT_METHOD,
        min_version=net_tls.Version[ctx.options.tls_version_server_min],
        max_version=net_tls.Version[ctx.options.tls_version_server_max],
        cipher_list=tuple(cipher_list),
        verify=verify,
        ca_path=ctx.options.ssl_verify_upstream_trusted_confdir,
        ca_pemfile=ctx.options.ssl_verify_upstream_trusted_ca,
        client_cert=client_cert,
    )

    tls_start.ssl_conn = SSL.Connection(ssl_ctx)
##### !!!!!! [KEY] default protocols and addons all here ####
/Users/jiaguo/codespace/OSR/mitmproxy-study/mitmproxy/addons/__init__.py
def default_addons():
    return [
        browser.Browser(),
        export.Export(),
        onboarding.Onboarding(),
        proxyauth.ProxyAuth(),
        proxyserver.Proxyserver(),
        dns_resolver.DnsResolver(),
        ... 
        tlsconfig.TlsConfig(),
        upstream_auth.UpstreamAuth(),
    ]


# =============================================================================    
### <auto generated> /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/contrib/kaitaistruct/tls_client_hello.py
#mitmproxy/addons/next_layer.py
def _next_layer(
    self, context: Context, data_client: bytes, data_server: bytes
): 
''' -> Layer | None:
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
'''

def _get_client_hello(
        self, context: Context, data_client: bytes
    ):  ''' -> ClientHello | None: '''

# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/proxy/layers/tls.py
def parse_client_hello(data: bytes) -> ClientHello | None:
    """
    Check if the supplied bytes contain a full ClientHello message,
    and if so, parse it.

    Returns:
        - A ClientHello object on success
        - None, if the TLS record is not complete

    Raises:
        - A ValueError, if the passed ClientHello is invalid
    """
    # Check if ClientHello is complete
    client_hello = get_client_hello(data)
    if client_hello:
        try:
            return ClientHello(client_hello[4:])
        except EOFError as e:
            raise ValueError("Invalid ClientHello") from e
    return None

# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/proxy/layer.py
# TLS package data came from here 
class NextLayer(Layer):
    layer: Layer | None
    """The next layer. To be set by an addon."""

    events: list[mevents.Event]
    """All events that happened before a decision was made."""

    _ask_on_start: bool
    
    def _data(self, connection: Connection):
        data = (
            e.data
            for e in self.events
            if isinstance(e, mevents.DataReceived) and e.connection == connection
        )
        return b"".join(data)

# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/net/tls.py
# /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/tls.py

### /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/master.py


