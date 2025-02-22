from mitmproxy import addons
from mitmproxy import master
from mitmproxy import options
from mitmproxy.addons import dumper
from mitmproxy.addons import errorcheck
from mitmproxy.addons import keepserving
from mitmproxy.addons import readfile
from mitmproxy.addons import termlog


class DumpMaster(master.Master):
    def __init__(
        self,
        options: options.Options,
        loop=None,
        with_termlog=True,
        with_dumper=True,
    ) -> None:
        super().__init__(options, event_loop=loop)
        import traceback,inspect
        print("[[[[[[Jia]]]]]] ",inspect.currentframe(), __file__, __name__)
        print("[[[[[[Jia]]]]]] traceback.print_stack() : ", traceback.print_stack())        
        if with_termlog:
            self.addons.add(termlog.TermLog())
        self.addons.add(*addons.default_addons())
        if with_dumper:
            self.addons.add(dumper.Dumper())
        self.addons.add(
            keepserving.KeepServing(),
            readfile.ReadFileStdin(),
            errorcheck.ErrorCheck(),
        )
