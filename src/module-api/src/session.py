import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry
import threading

# Network configuration
# Network requests have retries 
retry_strategy = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["POST"],
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=100, pool_connections=100)

# Thread local configuration
thread_local_data = threading.local()


def get_thread_local_session() -> requests.Session:
    """
    Get the session from the thread local data

    The session is created only once and then reused.

    Returns: the session
    """
    if not hasattr(thread_local_data, "session"):
        thread_local_data.session = requests.Session()
        thread_local_data.session.mount("https://", adapter)
    return thread_local_data.session
