
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

# !!!!! certificates mocked by mitmproxy is generated in file below 
# /Users/jiaguo/codespace/OSR/mitmproxy-study/mitmproxy/certs.py
class CertStore:
    STORE_CAP = 100
    certs: dict[TCertId, CertStoreEntry]
    expire_queue: list[CertStoreEntry]
    
    @classmethod
    def from_store(
        cls,
        path: Path | str,
        basename: str,
        key_size: int,
        passphrase: bytes | None = None,
    ) -> "CertStore":
        
    @classmethod
    def from_files(
        cls, ca_file: Path, dhparam_file: Path, passphrase: bytes | None = None
    ) -> "CertStore":
        raw = ca_file.read_bytes()
        key = load_pem_private_key(raw, passphrase)
        dh = cls.load_dhparam(dhparam_file)
        certs = re.split(rb"(?=-----BEGIN CERTIFICATE-----)", raw)
        ca = Cert.from_pem(certs[1])
        if len(certs) > 2:
            chain_file: Path | None = ca_file
        else:
            chain_file = None
        return cls(key, ca, chain_file, dh)          

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
# very first ClientHello initative by client 
class ClientHello:
    """
    A TLS ClientHello is the first message sent by the client when initiating TLS.
    """

    _raw_bytes: bytes

    def __init__(self, raw_client_hello: bytes, dtls: bool = False):
        """Create a TLS ClientHello object from raw bytes."""
        self._raw_bytes = raw_client_hello
        if dtls:
            self._client_hello = dtls_client_hello.DtlsClientHello(
                KaitaiStream(io.BytesIO(raw_client_hello))
            )
        else:
            self._client_hello = tls_client_hello.TlsClientHello(
                KaitaiStream(io.BytesIO(raw_client_hello))
            )

### /home/jiaguo/Documents/codespace/Tools/mitmproxy-study/mitmproxy/master.py

#/Users/jiaguo/codespace/OSR/mitmproxy-study/mitmproxy/proxy/__init__.py
#This module contains mitmproxy's core network proxy.

#/Users/jiaguo/codespace/OSR/mitmproxy-study/mitmproxy/addons/browser.py
# >>> port 8080 
class Browser:
    browser: list[subprocess.Popen] = []
    tdir: list[tempfile.TemporaryDirectory] = []
    ....

    self.browser.append(
        subprocess.Popen(
            [
                *cmd,
                "--user-data-dir=%s" % str(tdir.name),
                "--proxy-server={}:{}".format(
                    ctx.options.listen_host or "127.0.0.1",
                    ctx.options.listen_port or "8080",
                ),
                "--disable-fre",
                "--no-default-browser-check",
                "--no-first-run",
                "--disable-extensions",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    )

#########################################################################################################
#########################################################################################################
(venv) jiaguo@ub2204:~/codespace/Tools/net/mitmproxy-study/release/dist$ ./mitmdump 
 ===== Hello Jia Guo main ====== 
[[[[[[Jia]]]]]]  <frame at 0x107d440, file 'mitmproxy/addons/tlsconfig.py', line 30, code <module>> /tmp/_MEIJrF8xz/mitmproxy/addons/tlsconfig.pyc mitmproxy.addons.tlsconfig
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 143, in mitmdump
  File "<frozen importlib._bootstrap>", line 1078, in _handle_fromlist
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "PyInstaller/loader/pyimod02_importers.py", line 352, in exec_module
  File "mitmproxy/tools/dump.py", line 1, in <module>
  File "<frozen importlib._bootstrap>", line 1078, in _handle_fromlist
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "PyInstaller/loader/pyimod02_importers.py", line 352, in exec_module
  File "mitmproxy/addons/__init__.py", line 27, in <module>
  File "<frozen importlib._bootstrap>", line 1078, in _handle_fromlist
  File "<frozen importlib._bootstrap>", line 241, in _call_with_frames_removed
  File "<frozen importlib._bootstrap>", line 1027, in _find_and_load
  File "<frozen importlib._bootstrap>", line 1006, in _find_and_load_unlocked
  File "<frozen importlib._bootstrap>", line 688, in _load_unlocked
  File "PyInstaller/loader/pyimod02_importers.py", line 352, in exec_module
  File "mitmproxy/addons/tlsconfig.py", line 31, in <module>
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x13bc500, file 'mitmproxy/tools/main.py', line 68, code main> /tmp/_MEIJrF8xz/mitmproxy/tools/main.pyc mitmproxy.tools.main
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/tools/main.py", line 69, in main
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x7f80b30949f0, file 'mitmproxy/tools/dump.py', line 21, code __init__> /tmp/_MEIJrF8xz/mitmproxy/tools/dump.pyc mitmproxy.tools.dump
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/tools/main.py", line 72, in main
  File "mitmproxy/tools/dump.py", line 22, in __init__
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]in default_addon() :  /tmp/_MEIJrF8xz/mitmproxy/addons/__init__.pyc mitmproxy.addons
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/tools/main.py", line 72, in main
  File "mitmproxy/tools/dump.py", line 25, in __init__
  File "mitmproxy/addons/__init__.py", line 39, in default_addons
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[18:36:23.700] Hello default_addons viplog 

[[[[[[Jia]]]]]]  <frame at 0x7f80b29f0c80, file 'mitmproxy/addons/proxyserver.py', line 286, code setup_servers> /tmp/_MEIJrF8xz/mitmproxy/addons/proxyserver.pyc mitmproxy.addons.proxyserver
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/tools/main.py", line 129, in main
  File "mitmproxy/master.py", line 56, in run
  File "mitmproxy/addons/proxyserver.py", line 287, in setup_servers
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[18:36:23.730] HTTP(S) proxy listening at *:8080.

[18:38:44.147][127.0.0.1:36118] client connect
[18:38:44.298][127.0.0.1:36118] client disconnect
[18:38:44.300][127.0.0.1:36118] error establishing server connection: client disconnected
127.0.0.1:36118: GET http://example.com/favicon.ico
 << client disconnected
[18:38:47.540][127.0.0.1:36128] client connect
[18:38:47.909][127.0.0.1:36128] server connect ocsp.digicert.com:80 (152.195.38.76:80)
127.0.0.1:36128: POST http://ocsp.digicert.com/
              << 200 OK 471b

[18:39:01.018][127.0.0.1:36684] client connect
[18:39:01.076][127.0.0.1:36684] server connect gist-queue-consumer-api.cloud.gist.build:443 (34.120.32.134:443)
[[[[[[Jia]]]]]]  <frame at 0x144a8f0, file 'mitmproxy/tls.py', line 25, code __init__> /tmp/_MEIJrF8xz/mitmproxy/tls.pyc mitmproxy.tls
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layer.py", line 265, in handle_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 879, in _handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 935, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 775, in passthrough
  File "mitmproxy/proxy/layer.py", line 267, in handle_event
  File "mitmproxy/proxy/layer.py", line 137, in handle_event
  File "mitmproxy/proxy/layer.py", line 228, in __continue
  File "mitmproxy/proxy/layer.py", line 191, in __process
  File "mitmproxy/proxy/layer.py", line 284, in _handle_event
  File "mitmproxy/proxy/layer.py", line 298, in _ask
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 98, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 473, in event_to_child
  File "mitmproxy/proxy/tunnel.py", line 153, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 70, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 547, in receive_handshake_data
  File "mitmproxy/proxy/layers/tls.py", line 86, in parse_client_hello
  File "mitmproxy/tls.py", line 26, in __init__
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x1504cf0, file 'mitmproxy/addons/tlsconfig.py', line 161, code tls_start_client> /tmp/_MEIJrF8xz/mitmproxy/addons/tlsconfig.pyc mitmproxy.addons.tlsconfig
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 344, in hook_task
  File "mitmproxy/proxy/mode_servers.py", line 70, in handle_hook
  File "mitmproxy/addonmanager.py", line 234, in handle_lifecycle
  File "mitmproxy/addonmanager.py", line 288, in trigger_event
  File "mitmproxy/addonmanager.py", line 265, in invoke_addon
  File "mitmproxy/addons/tlsconfig.py", line 162, in tls_start_client
[[[[[[Jia]]]]]] traceback.print_stack() :  None
tls_start: TlsData(conn=Client({'id': '…3f8020', 'address': None, 'peername': ('127.0.0.1', 36684), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'gist-queue-consumer-api.cloud.gist.build', 'timestamp_start': 1682159941.0177877}), context=Context(
  Client({'id': '…3f8020', 'address': None, 'peername': ('127.0.0.1', 36684), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'gist-queue-consumer-api.cloud.gist.build', 'timestamp_start': 1682159941.0177877}),
  Server({'id': '…df8364', 'address': ('gist-queue-consumer-api.cloud.gist.build', 443), 'peername': ('34.120.32.134', 443), 'sockname': ('192.168.71.139', 50324), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'certificate_list': [<Cert(cn='gist-queue-consumer-api.cloud.gist.build', altnames=['gist-queue-consumer-api.cloud.gist.build', 'gist-queue-composer-api.cloud.gist.build', 'gist-realtime-api.cloud.gist.build'])>, <Cert(cn='GTS CA 1D4', altnames=[])>, <Cert(cn='GTS Root R1', altnames=[])>], 'alpn': b'h2', 'alpn_offers': (b'h2', b'http/1.1'), 'cipher': 'TLS_AES_256_GCM_SHA384', 'tls_version': 'TLSv1.3', 'sni': 'gist-queue-consumer-api.cloud.gist.build', 'timestamp_start': 1682159941.0304766, 'timestamp_tls_setup': 1682159941.198649, 'timestamp_tcp_setup': 1682159941.0760136}),
  layers=[[HttpProxy(state: handle_event), HttpLayer(regular, conns: 2), HttpStream(id=1, passthrough), ServerTLSLayer(open 'gist-queue-consumer-api.cloud.gist.build' b'h2'), ClientTLSLayer(establishing 'gist-queue-consumer-api.cloud.gist.build' None)]]
), ssl_conn=None, is_dtls=False)
[18:39:01.249][127.0.0.1:36684] Client TLS handshake failed. The client does not trust the proxy's certificate for gist-queue-consumer-api.cloud.gist.build (sslv3 alert bad certificate)

#####################################################################################################################
[18:39:23.348][127.0.0.1:41274] client connect
[18:39:23.787][127.0.0.1:41274] server connect azwus1-client-s.gateway.messenger.live.com:443 (13.83.65.43:443)
[[[[[[Jia]]]]]]  <frame at 0x144a8f0, file 'mitmproxy/tls.py', line 25, code __init__> /tmp/_MEIJrF8xz/mitmproxy/tls.pyc mitmproxy.tls
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layer.py", line 265, in handle_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 879, in _handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 935, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 775, in passthrough
  File "mitmproxy/proxy/layer.py", line 267, in handle_event
  File "mitmproxy/proxy/layer.py", line 137, in handle_event
  File "mitmproxy/proxy/layer.py", line 228, in __continue
  File "mitmproxy/proxy/layer.py", line 191, in __process
  File "mitmproxy/proxy/layer.py", line 284, in _handle_event
  File "mitmproxy/proxy/layer.py", line 298, in _ask
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 98, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 473, in event_to_child
  File "mitmproxy/proxy/tunnel.py", line 153, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 70, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 547, in receive_handshake_data
  File "mitmproxy/proxy/layers/tls.py", line 86, in parse_client_hello
  File "mitmproxy/tls.py", line 26, in __init__
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x1504cf0, file 'mitmproxy/addons/tlsconfig.py', line 161, code tls_start_client> /tmp/_MEIJrF8xz/mitmproxy/addons/tlsconfig.pyc mitmproxy.addons.tlsconfig
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 344, in hook_task
  File "mitmproxy/proxy/mode_servers.py", line 70, in handle_hook
  File "mitmproxy/addonmanager.py", line 234, in handle_lifecycle
  File "mitmproxy/addonmanager.py", line 288, in trigger_event
  File "mitmproxy/addonmanager.py", line 265, in invoke_addon
  File "mitmproxy/addons/tlsconfig.py", line 162, in tls_start_client
[[[[[[Jia]]]]]] traceback.print_stack() :  None
tls_start: TlsData(conn=Client({'id': '…24b962', 'address': None, 'peername': ('127.0.0.1', 41274), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'azwus1-client-s.gateway.messenger.live.com', 'timestamp_start': 1682159963.3474882}), context=Context(
  Client({'id': '…24b962', 'address': None, 'peername': ('127.0.0.1', 41274), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'azwus1-client-s.gateway.messenger.live.com', 'timestamp_start': 1682159963.3474882}),
  Server({'id': '…55c778', 'address': ('azwus1-client-s.gateway.messenger.live.com', 443), 'peername': ('13.83.65.43', 443), 'sockname': ('192.168.71.139', 37936), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'certificate_list': [<Cert(cn='apis.skype.com', altnames=['*.gateway.messenger.live.com', 'api.chat.skype.net', '*.chat.skype.net', 'apis.skype.com', 'api.skype.net', 'df-api.skype.net', 'df-apis.skype.com', '*.api.skype.net', '*.apis.skype.com'])>, <Cert(cn='Microsoft Azure TLS Issuing CA 02', altnames=[])>], 'alpn': b'', 'alpn_offers': (b'h2', b'http/1.1'), 'cipher': 'ECDHE-RSA-AES256-GCM-SHA384', 'tls_version': 'TLSv1.2', 'sni': 'azwus1-client-s.gateway.messenger.live.com', 'timestamp_start': 1682159963.3515537, 'timestamp_tls_setup': 1682159964.4029737, 'timestamp_tcp_setup': 1682159963.7868536}),
  layers=[[HttpProxy(state: handle_event), HttpLayer(regular, conns: 2), HttpStream(id=1, passthrough), ServerTLSLayer(open 'azwus1-client-s.gateway.messenger.live.com' b''), ClientTLSLayer(establishing 'azwus1-client-s.gateway.messenger.live.com' None)]]
), ssl_conn=None, is_dtls=False)
[18:39:24.434][127.0.0.1:41274] Client TLS handshake failed. The client does not trust the proxy's certificate for azwus1-client-s.gateway.messenger.live.com (OpenSSL Error([('SSL routines', '', 'sslv3 alert certificate unknown')]))
[18:39:24.439][127.0.0.1:41274] client disconnect
[18:39:24.442][127.0.0.1:41274] server disconnect azwus1-client-s.gateway.messenger.live.com:443 (13.83.65.43:443)


#######################################
18:39:13.743][127.0.0.1:42880] server connect www.msftconnecttest.com:80 (23.209.116.56:80)
[18:39:13.750][127.0.0.1:42888] server connect azwus1-client-s.gateway.messenger.live.com:443 (13.83.65.43:443)
[[[[[[Jia]]]]]]  <frame at 0x144a8f0, file 'mitmproxy/tls.py', line 25, code __init__> /tmp/_MEIJrF8xz/mitmproxy/tls.pyc mitmproxy.tls
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layer.py", line 265, in handle_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 879, in _handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 935, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 775, in passthrough
  File "mitmproxy/proxy/layer.py", line 267, in handle_event
  File "mitmproxy/proxy/layer.py", line 137, in handle_event
  File "mitmproxy/proxy/layer.py", line 228, in __continue
  File "mitmproxy/proxy/layer.py", line 191, in __process
  File "mitmproxy/proxy/layer.py", line 284, in _handle_event
  File "mitmproxy/proxy/layer.py", line 298, in _ask
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 98, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 473, in event_to_child
  File "mitmproxy/proxy/tunnel.py", line 153, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 70, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 547, in receive_handshake_data
  File "mitmproxy/proxy/layers/tls.py", line 86, in parse_client_hello
  File "mitmproxy/tls.py", line 26, in __init__
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x1504cf0, file 'mitmproxy/addons/tlsconfig.py', line 161, code tls_start_client> /tmp/_MEIJrF8xz/mitmproxy/addons/tlsconfig.pyc mitmproxy.addons.tlsconfig
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 344, in hook_task
  File "mitmproxy/proxy/mode_servers.py", line 70, in handle_hook
  File "mitmproxy/addonmanager.py", line 234, in handle_lifecycle
  File "mitmproxy/addonmanager.py", line 288, in trigger_event
  File "mitmproxy/addonmanager.py", line 265, in invoke_addon
  File "mitmproxy/addons/tlsconfig.py", line 162, in tls_start_client
[[[[[[Jia]]]]]] traceback.print_stack() :  None
tls_start: TlsData(conn=Client({'id': '…dc509e', 'address': None, 'peername': ('127.0.0.1', 42854), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'browser.pipe.aria.microsoft.com', 'timestamp_start': 1682159953.1357133}), context=Context(
  Client({'id': '…dc509e', 'address': None, 'peername': ('127.0.0.1', 42854), 'sockname': ('127.0.0.1', 8080), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'alpn_offers': [b'h2', b'http/1.1'], 'sni': 'browser.pipe.aria.microsoft.com', 'timestamp_start': 1682159953.1357133}),
  Server({'id': '…b1f15f', 'address': ('browser.pipe.aria.microsoft.com', 443), 'peername': ('104.46.162.226', 443), 'sockname': ('192.168.71.139', 60014), 'state': <ConnectionState.OPEN: 3>, 'tls': True, 'certificate_list': [<Cert(cn='*.events.data.microsoft.com', altnames=['*.events.data.microsoft.com', 'events.data.microsoft.com', '*.pipe.aria.microsoft.com', 'pipe.skype.com', '*.pipe.skype.com', '*.mobile.events.data.microsoft.com', 'mobile.events.data.microsoft.com', '*.events.data.msn.com', 'events.data.msn.com', '*.events.data.msn.cn', 'events.data.msn.cn', 'oca.microsoft.com', 'watson.microsoft.com', '*.vortex.data.microsoft.com', 'vortex.data.microsoft.com'])>, <Cert(cn='Microsoft Azure TLS Issuing CA 01', altnames=[])>], 'alpn': b'', 'alpn_offers': (b'h2', b'http/1.1'), 'cipher': 'ECDHE-RSA-AES256-GCM-SHA384', 'tls_version': 'TLSv1.2', 'sni': 'browser.pipe.aria.microsoft.com', 'timestamp_start': 1682159953.154839, 'timestamp_tls_setup': 1682159953.8339295, 'timestamp_tcp_setup': 1682159953.4728754}),
  layers=[[HttpProxy(state: handle_event), HttpLayer(regular, conns: 2), HttpStream(id=1, passthrough), ServerTLSLayer(open 'browser.pipe.aria.microsoft.com' b''), ClientTLSLayer(establishing 'browser.pipe.aria.microsoft.com' None)]]
), ssl_conn=None, is_dtls=False)
[18:39:13.900][127.0.0.1:42854] Client TLS handshake failed. The client does not trust the proxy's certificate for browser.pipe.aria.microsoft.com (OpenSSL Error([('SSL routines', '', 'sslv3 alert certificate unknown')]))



############################### TLS Connection Established ###########################
###################  DUMP ======================

[11:53:47.743][127.0.0.1:40788] client connect
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/mode_servers.py", line 211, in handle_tcp_connection
  File "mitmproxy/proxy/server.py", line 151, in handle_client
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: Start({})
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 291, in handle_connection
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: DataReceived(client, b'CONNECT gist-queue-consumer-api.cloud.gist.build:443 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: gist-queue-consumer-api.cloud.gist.build:443\r\n\r\n')
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: Reply(NextLayerHook(data=NextLayer:HttpLayer(regular, conns: 0)), None)
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: [[[[[[Jia]]]]]]  <frame at 0x7f2622a13140, file 'mitmproxy/connection.py', line 133, code tls_established> /tmp/_MEIvZmBd8/mitmproxy/connection.pyc mitmproxy.connection
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 361, in server_event
  File "mitmproxy/proxy/events.py", line 104, in __repr__
  File "dataclasses.py", line 405, in wrapper
  File "<string>", line 3, in __repr__
  File "mitmproxy/http.py", line 1287, in __repr__
  File "mitmproxy/connection.py", line 198, in __str__
  File "mitmproxy/connection.py", line 134, in tls_established
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x7f2622a13140, file 'mitmproxy/connection.py', line 133, code tls_established> /tmp/_MEIvZmBd8/mitmproxy/connection.pyc mitmproxy.connection
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 361, in server_event
  File "mitmproxy/proxy/events.py", line 104, in __repr__
  File "dataclasses.py", line 405, in wrapper
  File "<string>", line 3, in __repr__
  File "mitmproxy/http.py", line 1287, in __repr__
  File "mitmproxy/connection.py", line 294, in __str__
  File "mitmproxy/connection.py", line 134, in tls_established
[[[[[[Jia]]]]]] traceback.print_stack() :  None
Reply(HttpConnectHook(flow=<HTTPFlow
  request = Request(CONNECT gist-queue-consumer-api.cloud.gist.build:443)
  client_conn = Client(127.0.0.1:40788, state=open)
  server_conn = Server(<no address>, state=closed)>), None)

################################### TLS Server reply #####################################
===   traceback.print_stack() ===:  None


 event: [[[[[[Jia]]]]]]  <frame at 0x7f2622a13140, file 'mitmproxy/connection.py', line 133, code tls_established> /tmp/_MEIvZmBd8/mitmproxy/connection.pyc mitmproxy.connection
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 361, in server_event
  File "mitmproxy/proxy/events.py", line 104, in __repr__
  File "dataclasses.py", line 405, in wrapper
  File "<string>", line 3, in __repr__
  File "mitmproxy/http.py", line 1287, in __repr__
  File "mitmproxy/connection.py", line 198, in __str__
  File "mitmproxy/connection.py", line 134, in tls_established
[[[[[[Jia]]]]]] traceback.print_stack() :  None
[[[[[[Jia]]]]]]  <frame at 0x7f2622a13140, file 'mitmproxy/connection.py', line 133, code tls_established> /tmp/_MEIvZmBd8/mitmproxy/connection.pyc mitmproxy.connection
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 361, in server_event
  File "mitmproxy/proxy/events.py", line 104, in __repr__
  File "dataclasses.py", line 405, in wrapper
  File "<string>", line 3, in __repr__
  File "mitmproxy/http.py", line 1287, in __repr__
  File "mitmproxy/connection.py", line 294, in __str__
  File "mitmproxy/connection.py", line 134, in tls_established
[[[[[[Jia]]]]]] traceback.print_stack() :  None
Reply(HttpConnectHook(flow=<HTTPFlow
  request = Request(CONNECT gist-queue-consumer-api.cloud.gist.build:443)
  client_conn = Client(127.0.0.1:40788, state=open)
  server_conn = Server(<no address>, state=closed)>), None)
[11:53:47.805][127.0.0.1:40788] server connect gist-queue-consumer-api.cloud.gist.build:443 (34.120.32.134:443)
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 247, in open_connection
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: Reply(OpenConnection({'connection': Server({'id': '…e3eb0a', 'address': ('gist-queue-consumer-api.cloud.gist.build', 443), 'peername': ('34.120.32.134', 443), 'sockname': ('192.168.71.137', 37480), 'state': <ConnectionState.OPEN: 3>, 'timestamp_start': 1682222027.7543836, 'timestamp_tcp_setup': 1682222027.8050983})}), None)
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 291, in handle_connection
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: DataReceived(client, b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03e\xa3\x90\x10\xbcTg\xcf(HJmJ\xdd\xe4\xdaZ\xa2\x8cMTc\xeb\x93\xb10\x0c\xff\xf7\xbeAQ \xbfb\xf2\x02\xbe\x12yHp\xb8\x02o\xb9\x96zT\xaeP\xdc)}\xe0\xcb^\x0f?KJA\xff@\x91\x00"\x13\x01\x13\x03\x13\x02\xc0+\xc0/\xcc\xa9\xcc\xa8\xc0,\xc00\xc0\n\xc0\t\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00-\x00+\x00\x00(gist-queue-consumer-api.cloud.gist.build\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00"\x00\n\x00\x08\x04\x03\x05\x03\x06\x03\x02\x03\x003\x00k\x00i\x00\x1d\x00 $\x86\x0b\x8eAr\x8b\xae\x95\x83\x90\xb0C\xbb\xeb\x95N\x975\xab\x99\xdeT\x83q\x8b\xb1UW\xa6=n\x00\x17\x00A\x04\xfa\xd6\x91\xdfj\xab\x88\xfcm\x91\xbf\x87\x98s\xdc\x7f\xd8\x0c\xea\x15\x96US\xd3\x9dQ\x1a\t\x0b\xd3\x81\xb9\xc7\x93f\xce\x05\xf8\xac<\xbe\x9d\xcb)\xca\xea\xf5\xb2*\xa6M\xf5\xa2\xe8\x8e2\x9blO\xb2\xb4\xfa5:\x00+\x00\x05\x04\x03\x04\x03\x03\x00\r\x00\x18\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01\x00-\x00\x02\x01\x01\x00\x1c\x00\x02@\x01\x00\x15\x00n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event


===   traceback.print_stack() ===:  None


 event: Reply(NextLayerHook(data=NextLayer:ServerTLSLayer(inactive None None)), None)
[[[[[[Jia]]]]]]  <frame at 0x7f2622a2cb20, file 'mitmproxy/tls.py', line 25, code __init__> /tmp/_MEIvZmBd8/mitmproxy/tls.pyc mitmproxy.tls
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 364, in server_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layer.py", line 265, in handle_event
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 879, in _handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 935, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/layers/http/__init__.py", line 775, in passthrough
  File "mitmproxy/proxy/layer.py", line 267, in handle_event
  File "mitmproxy/proxy/layer.py", line 137, in handle_event
  File "mitmproxy/proxy/layer.py", line 228, in __continue
  File "mitmproxy/proxy/layer.py", line 191, in __process
  File "mitmproxy/proxy/layer.py", line 284, in _handle_event
  File "mitmproxy/proxy/layer.py", line 298, in _ask
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 98, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 473, in event_to_child
  File "mitmproxy/proxy/tunnel.py", line 153, in event_to_child
  File "mitmproxy/proxy/layer.py", line 152, in handle_event
  File "mitmproxy/proxy/tunnel.py", line 70, in _handle_event
  File "mitmproxy/proxy/layers/tls.py", line 547, in receive_handshake_data
  File "mitmproxy/proxy/layers/tls.py", line 86, in parse_client_hello
  File "mitmproxy/tls.py", line 26, in __init__
[[[[[[Jia]]]]]] traceback.print_stack() :  None
=== inspect.currentframe ===  <frame at 0x26dd7f0, file 'mitmproxy/proxy/server.py', line 358, code server_event> /tmp/_MEIvZmBd8/mitmproxy/proxy/server.pyc mitmproxy.proxy.server
  File "mitmdump", line 3, in <module>
  File "mitmproxy/tools/main.py", line 155, in mitmdump
  File "mitmproxy/tools/main.py", line 132, in run
  File "asyncio/runners.py", line 44, in run
  File "asyncio/base_events.py", line 633, in run_until_complete
  File "asyncio/base_events.py", line 600, in run_forever
  File "asyncio/base_events.py", line 1896, in _run_once
  File "asyncio/events.py", line 80, in _run
  File "mitmproxy/proxy/server.py", line 346, in hook_task
  File "mitmproxy/proxy/server.py", line 359, in server_event
