
###########################################################################
# mitmproxy/master.py
###########################################################################


class Master:
    """
    The master handles mitmproxy's main event loop.
    """

    event_loop: asyncio.AbstractEventLoop

    def __init__(
        self,
        opts: options.Options,
        event_loop: asyncio.AbstractEventLoop | None = None,
    ):
        self.options: options.Options = opts or options.Options()
        self.commands = command.CommandManager(self)
        self.addons = addonmanager.AddonManager(self)
# ......
    async def run(self) -> None:
        old_handler = self.event_loop.get_exception_handler()
        self.event_loop.set_exception_handler(self._asyncio_exception_handler)
        try:
            self.should_exit.clear()

            if ec := self.addons.get("errorcheck"):
                await ec.shutdown_if_errored()
            if ps := self.addons.get("proxyserver"):
                await ps.setup_servers()
            if ec := self.addons.get("errorcheck"):
                await ec.shutdown_if_errored()
                ec.finish()
            await self.running()
            try:
                await self.should_exit.wait()
            finally:
                # .wait might be cancelled (e.g. by sys.exit)
                await self.done()
        finally:
            self.event_loop.set_exception_handler(old_handler)


###########################################################################
# mitmproxy/addons/proxyserver.py
###########################################################################

class Proxyserver(ServerManager):
    """
    This addon runs the actual proxy server.
    """

    connections: dict[tuple, ProxyConnectionHandler]
    servers: Servers

    is_running: bool
    _connect_addr: Address | None = None
    _update_task: asyncio.Task | None = None

    async def setup_servers(self) -> bool:
        import traceback,inspect
        print("[setup_servers] ",inspect.currentframe(), __file__, __name__)
        print("[setup_servers] traceback.print_stack() : ", traceback.print_stack())

        return await self.servers.update(
            [mode_specs.ProxyMode.parse(m) for m in ctx.options.mode]
        )    


###########################################################################
## [Server Setup (mode/protocol)] mitmproxy/proxy/mode_servers.py ##
###########################################################################
# which server mode mitm setup : reverse / regular / transparent etc... 
class AsyncioServerInstance(ServerInstance[M], metaclass=ABCMeta):
    _server: asyncio.Server | udp.UdpServer | None = None
 # .....
    async def listen(self, host: str, port: int) -> asyncio.Server | udp.UdpServer:
        if self.mode.transport_protocol == "tcp":
            # workaround for https://github.com/python/cpython/issues/89856:
            # We want both IPv4 and IPv6 sockets to bind to the same port.
            # This may fail (https://github.com/mitmproxy/mitmproxy/pull/5542#issuecomment-1222803291),
            # so we try to cover the 99% case and then give up and fall back to what asyncio does.
            if port == 0:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(("", 0))
                    fixed_port = s.getsockname()[1]
                    s.close()
                    return await asyncio.start_server(
                        self.handle_tcp_connection, host, fixed_port
                    )
                except Exception as e:
                    logger.debug(
                        f"Failed to listen on a single port ({e!r}), falling back to default behavior."
                    )
            return await asyncio.start_server(self.handle_tcp_connection, host, port)
        elif self.mode.transport_protocol == "udp":
            # create_datagram_endpoint only creates one socket, so the workaround above doesn't apply
            # NOTE once we do dual servers, we should consider creating sockets manually to ensure
            # both TCP and UDP listen to the same IPs and same ports
            return await udp.start_server(
                self.handle_udp_datagram,
                host,
                port,
            )
        else:
            raise AssertionError(self.mode.transport_protocol)



###########################################################################
## [Connection] mitmproxy/proxy/server.py ##
###########################################################################
# Loop forever -> one connection one loop server to handle all event happen to this connection 
class ConnectionHandler(metaclass=abc.ABCMeta):
    transports: MutableMapping[Connection, ConnectionIO]
    timeout_watchdog: TimeoutWatchdog
    client: Client
    max_conns: collections.defaultdict[Address, asyncio.Semaphore]
    layer: "layer.Layer"
    wakeup_timer: set[asyncio.Task]
    hook_tasks: set[asyncio.Task]

    def __init__(self, context: Context) -> None:
        self.client = context.client
        self.transports = {}
        self.max_conns = collections.defaultdict(lambda: asyncio.Semaphore(5))
        self.wakeup_timer = set()
        self.hook_tasks = set()

        # Ask for the first layer right away.
        # In a reverse proxy scenario, this is necessary as we would otherwise hang
        # on protocols that start with a server greeting.
        self.layer = layer.NextLayer(context, ask_on_start=True)
        self.timeout_watchdog = TimeoutWatchdog(self.on_timeout)

        # workaround for https://bugs.python.org/issue40124 / https://bugs.python.org/issue29930
        self._drain_lock = asyncio.Lock()
    
    async def handle_connection(self, connection: Connection) -> None:
        """
        Handle a connection for its entire lifetime.
        This means we read until EOF,
        but then possibly also keep on waiting for our side of the connection to be closed.
        """
        cancelled = None
        reader = self.transports[connection].reader
        assert reader
        # forever loop for one connections
        while True:
            try:
                data = await reader.read(65535)
                if not data:
                    raise OSError("Connection closed by peer.")
            except OSError:
                break
            except asyncio.CancelledError as e:
                cancelled = e
                break

            self.server_event(events.DataReceived(connection, data))

            try:
                await self.drain_writers()
            except asyncio.CancelledError as e:
                cancelled = e
                break

        if cancelled is None:
            connection.state &= ~ConnectionState.CAN_READ
        else:
            connection.state = ConnectionState.CLOSED

        self.server_event(events.ConnectionClosed(connection))

        if cancelled is None and connection.state is ConnectionState.CAN_WRITE:
            # we may still use this connection to *send* stuff,
            # even though the remote has closed their side of the connection.
            # to make this work we keep this task running and wait for cancellation.
            await asyncio.Event().wait()

        try:
            writer = self.transports[connection].writer
            assert writer
            writer.close()
        except OSError:
            pass
        self.transports.pop(connection)

        if cancelled:
            raise cancelled
