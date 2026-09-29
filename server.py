import os
import time
import hmac
import hashlib
import json
import urllib.request
import ssl
import certifi
import secrets

from http.server import BaseHTTPRequestHandler, HTTPServer


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

TUYA_ACCESS_ID = os.environ["TUYA_ACCESS_ID"]
TUYA_ACCESS_SECRET = os.environ["TUYA_ACCESS_SECRET"]

# A separate password/token used by the Fire tablet.
APP_API_KEY = os.environ["APP_API_KEY"]

TUYA_BASE_URL = "https://openapi.tuyaus.com"

LIGHTS = {
    "tall": "ebfa2eea2a7a8874caob1d",
    "salt": "eb486aac2949041878zaod",
    "desk": "ebf5388145cb15ad68vopp"
}

SSL_CONTEXT = ssl.create_default_context(
    cafile=certifi.where()
)


# ---------------------------------------------------------
# TUYA AUTHENTICATION
# ---------------------------------------------------------

def get_token():

    timestamp = str(int(time.time() * 1000))

    path = "/v1.0/token?grant_type=1"

    string_to_sign = (
        "GET\n"
        + hashlib.sha256(b"").hexdigest()
        + "\n\n"
        + path
    )

    sign_text = (
        TUYA_ACCESS_ID
        + timestamp
        + string_to_sign
    )

    signature = hmac.new(
        TUYA_ACCESS_SECRET.encode(),
        sign_text.encode(),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": TUYA_ACCESS_ID,
        "sign": signature,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "lang": "en"
    }

    request = urllib.request.Request(
        TUYA_BASE_URL + path,
        headers=headers,
        method="GET"
    )

    with urllib.request.urlopen(
        request,
        context=SSL_CONTEXT,
        timeout=15
    ) as response:

        result = json.loads(
            response.read().decode()
        )

    if not result.get("success"):
        raise Exception(
            "Could not obtain Tuya token"
        )

    return result["result"]["access_token"]


# ---------------------------------------------------------
# SEND COMMAND TO ONE TUYA PLUG
# ---------------------------------------------------------

def send_command(device_id, value):

    token = get_token()

    path = (
        f"/v1.0/iot-03/devices/"
        f"{device_id}/commands"
    )

    body = {
        "commands": [
            {
                "code": "switch_1",
                "value": value
            }
        ]
    }

    timestamp = str(int(time.time() * 1000))

    body_bytes = json.dumps(
        body,
        separators=(",", ":")
    ).encode()

    body_hash = hashlib.sha256(
        body_bytes
    ).hexdigest()

    string_to_sign = (
        "POST\n"
        + body_hash
        + "\n\n"
        + path
    )

    sign_text = (
        TUYA_ACCESS_ID
        + token
        + timestamp
        + string_to_sign
    )

    signature = hmac.new(
        TUYA_ACCESS_SECRET.encode(),
        sign_text.encode(),
        hashlib.sha256
    ).hexdigest().upper()

    headers = {
        "client_id": TUYA_ACCESS_ID,
        "access_token": token,
        "sign": signature,
        "sign_method": "HMAC-SHA256",
        "t": timestamp,
        "lang": "en",
        "Content-Type": "application/json"
    }

    request = urllib.request.Request(
        TUYA_BASE_URL + path,
        data=body_bytes,
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(
        request,
        context=SSL_CONTEXT,
        timeout=15
    ) as response:

        result = json.loads(
            response.read().decode()
        )

    if not result.get("success"):
        raise Exception(
            f"Tuya command failed: {result}"
        )

    return result


# ---------------------------------------------------------
# HTTP SERVER
# ---------------------------------------------------------

class Handler(BaseHTTPRequestHandler):

    def authorized(self):

        supplied_key = self.headers.get(
            "X-API-Key",
            ""
        )

        return secrets.compare_digest(
            supplied_key,
            APP_API_KEY
        )

    def do_GET(self):

        # Simple health check for Render
        if self.path == "/":

            self.send_json({
                "success": True,
                "service": "Light Control"
            })

            return

        self.send_json(
            {
                "success": False,
                "error": "Not found"
            },
            404
        )

    def do_POST(self):

        # Don't allow strangers on the internet
        # to control the lights.
        if not self.authorized():

            self.send_json(
                {
                    "success": False,
                    "error": "Unauthorized"
                },
                401
            )

            return

        parts = self.path.strip("/").split("/")

        # -------------------------------------------------
        # ALL LIGHTS ON
        # -------------------------------------------------

        if self.path == "/on":

            self.control_all(True)

            return

        # -------------------------------------------------
        # ALL LIGHTS OFF
        # -------------------------------------------------

        if self.path == "/off":

            self.control_all(False)

            return

        # -------------------------------------------------
        # INDIVIDUAL LIGHT
        #
        # /tall/on
        # /tall/off
        # /salt/on
        # etc.
        # -------------------------------------------------

        if len(parts) == 2:

            light_name = parts[0]
            action = parts[1]

            if (
                light_name in LIGHTS
                and action in ["on", "off"]
            ):

                value = action == "on"

                try:

                    send_command(
                        LIGHTS[light_name],
                        value
                    )

                    self.send_json({
                        "success": True,
                        "light": light_name,
                        "state": value
                    })

                except Exception as e:

                    print(
                        f"ERROR controlling "
                        f"{light_name}: {e}"
                    )

                    self.send_json(
                        {
                            "success": False,
                            "error":
                                "Could not control light"
                        },
                        500
                    )

                return

        self.send_json(
            {
                "success": False,
                "error": "Unknown command"
            },
            404
        )

    def control_all(self, value):

        failures = []

        for name, device_id in LIGHTS.items():

            try:

                send_command(
                    device_id,
                    value
                )

            except Exception as e:

                print(
                    f"ERROR controlling "
                    f"{name}: {e}"
                )

                failures.append(name)

        if failures:

            self.send_json(
                {
                    "success": False,
                    "failed": failures
                },
                500
            )

        else:

            self.send_json({
                "success": True,
                "state": value
            })

    def send_json(
        self,
        data,
        status=200
    ):

        response = json.dumps(
            data
        ).encode()

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(response))
        )

        self.end_headers()

        self.wfile.write(response)

    def log_message(
        self,
        format,
        *args
    ):

        print(format % args)


# ---------------------------------------------------------
# START SERVER
# ---------------------------------------------------------

PORT = int(
    os.environ.get(
        "PORT",
        "8080"
    )
)

server = HTTPServer(
    ("0.0.0.0", PORT),
    Handler
)

print(
    f"Light Control server "
    f"running on port {PORT}"
)

server.serve_forever()
