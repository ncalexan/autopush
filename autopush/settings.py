"""Autopush Settings Object and Setup"""
import socket
import urlparse

from cryptography.fernet import Fernet
from twisted.internet import reactor
from twisted.web.client import Agent, HTTPConnectionPool

from autopush.db import (
    get_router_table,
    get_storage_table,
    get_message_table,
    get_receipts_table,
    preflight_check,
    Storage,
    Router,
    Message,
    Receipts,
)
from autopush.metrics import (
    DatadogMetrics,
    TwistedMetrics,
    SinkMetrics,
)
from autopush.router import (
    APNSRouter,
    GCMRouter,
    SimpleRouter,
    WebPushRouter,
)
from autopush.utils import canonical_url, is_same_origin, resolve_ip


class AutopushSettings(object):
    """Main Autopush Settings Object"""
    options = ["crypto_key", "hostname", "min_ping_interval",
               "max_data"]

    def __init__(self,
                 crypto_key=None,
                 datadog_api_key=None,
                 datadog_app_key=None,
                 datadog_flush_interval=None,
                 hostname=None,
                 port=None,
                 router_scheme=None,
                 router_hostname=None,
                 router_port=None,
                 endpoint_scheme=None,
                 endpoint_hostname=None,
                 endpoint_port=None,
                 receipts_scheme=None,
                 receipts_hostname=None,
                 receipts_port=8720,
                 router_conf={},
                 router_tablename="router",
                 router_read_throughput=5,
                 router_write_throughput=5,
                 storage_tablename="storage",
                 storage_read_throughput=5,
                 storage_write_throughput=5,
                 message_tablename="message",
                 message_read_throughput=5,
                 message_write_throughput=5,
                 receipts_tablename="receipts",
                 receipts_read_throughput=5,
                 receipts_write_throughput=5,
                 statsd_host="localhost",
                 statsd_port=8125,
                 resolve_hostname=False,
                 max_data=4096,
                 enable_cors=False):
        """Initialize the Settings object

        Upon creation, the HTTP agent will initialize, all configured routers
        will be setup and started, logging will be started, and the database
        will have a preflight check done.

        """
        # Use a persistent connection pool for HTTP requests.
        pool = HTTPConnectionPool(reactor)
        self.agent = Agent(reactor, connectTimeout=5, pool=pool)

        # Metrics setup
        if datadog_api_key:
            self.metrics = DatadogMetrics(
                api_key=datadog_api_key,
                app_key=datadog_app_key,
                flush_interval=datadog_flush_interval
            )
        elif statsd_host:
            self.metrics = TwistedMetrics(statsd_host, statsd_port)
        else:
            self.metrics = SinkMetrics()

        key = crypto_key or Fernet.generate_key()
        self.fernet = Fernet(key)
        self.crypto_key = key

        self.max_data = max_data
        self.clients = {}

        # Setup hosts/ports/urls
        default_hostname = socket.gethostname()
        self.hostname = hostname or default_hostname
        if resolve_hostname:
            self.hostname = resolve_ip(self.hostname)

        self.port = port
        self.endpoint_hostname = endpoint_hostname or self.hostname
        self.router_hostname = router_hostname or self.hostname
        self.receipts_hostname = receipts_hostname or self.hostname

        self.router_conf = router_conf
        self.router_url = canonical_url(
            router_scheme or 'http',
            self.router_hostname,
            router_port
        )

        self.endpoint_url = canonical_url(
            endpoint_scheme or 'http',
            self.endpoint_hostname,
            endpoint_port
        )

        self.receipts_uri = urlparse.urlsplit(canonical_url(
            receipts_scheme or 'http',
            self.receipts_hostname,
            receipts_port
        ))

        # Database objects
        self.router_table = get_router_table(router_tablename,
                                             router_read_throughput,
                                             router_write_throughput)
        self.storage_table = get_storage_table(storage_tablename,
                                               storage_read_throughput,
                                               storage_write_throughput)
        self.message_table = get_message_table(message_tablename,
                                               message_read_throughput,
                                               message_write_throughput)
        self.receipts_table = get_receipts_table(receipts_tablename,
                                                 receipts_read_throughput,
                                                 receipts_write_throughput)
        self.storage = Storage(self.storage_table, self.metrics)
        self.router = Router(self.router_table, self.metrics)
        self.message = Message(self.message_table, self.metrics)
        self.receipts = Receipts(self.receipts_table, self.metrics)

        # Run preflight check
        preflight_check(self.storage, self.router)

        # CORS
        self.cors = enable_cors

        # Setup the routers
        self.routers = {}
        self.routers["simplepush"] = SimpleRouter(self, None)
        self.routers["webpush"] = WebPushRouter(self, None)
        if 'apns' in router_conf:
            self.routers["apns"] = APNSRouter(self, router_conf["apns"])
        if 'gcm' in router_conf:
            self.routers["gcm"] = GCMRouter(self, router_conf["gcm"])

    def update(self, **kwargs):
        """Update the arguments, if a ``crypto_key`` is in kwargs then the
        ``self.fernet`` attribute will be initialized"""
        for key, val in kwargs.items():
            if key == "crypto_key":
                self.fernet = Fernet(val)
            else:
                setattr(self, key, val)

    def parse_push_receipt(self, receipt):
        """Extracts push receipt parameters from a receipt subscription URL.

        Returns a (uaid, chid, receipt_id) tuple. Raises ValueError or
        InvalidToken if the URL is malformed.
        """
        uri = urlparse.urlsplit(receipt)
        if not is_same_origin(uri, self.receipts_uri):
            raise ValueError("Mismatched receipts origin")

        if not uri.path.startswith("/r/"):
            raise ValueError("Invalid path prefix")

        info = self.fernet.decrypt(uri.path[3:].encode("utf8")).split(":")
        if len(info) != 4:
            raise ValueError("Wrong receipt token components")

        kind, uaid, chid, receipt_id = info
        if kind != "r":
            raise ValueError("Wrong receipt token kind")

        return (uaid, chid, receipt_id)

    def make_receipt_endpoint(self, uaid, chid, receipt_id):
        """Create a receipt subscription endpoint from the identifiers"""
        return '%s/r/%s' % (self.receipts_uri.geturl(), self.fernet.encrypt(
            ':'.join(['r', uaid, chid, receipt_id]).encode('utf8')))

    def make_endpoint(self, uaid, chid):
        """ Create an endpoint from the identifiers"""
        return self.endpoint_url + '/push/' + \
            self.fernet.encrypt((uaid + ':' + chid).encode('utf8'))
