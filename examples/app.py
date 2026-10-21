"""Offline application for the intentionally bloated image demo."""

import requests

request = requests.Request("GET", "https://example.invalid/demo").prepare()
print(f"Demo application prepared {request.method} {request.url}; no request sent.")
