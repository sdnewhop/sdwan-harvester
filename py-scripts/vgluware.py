#!/usr/bin/python3

from json import loads
from ssl import CERT_NONE

from websocket import WebSocket
from websocket import _exceptions as ws_exception


def main(addr):
    """
    Get gluware version with websocket

    :param addr: ip address of host (str)
    :return: version (str)
    """

    # Turn off SSL certificate checking
    ssl_cert_off = {"cert_reqs": CERT_NONE}
    ws = WebSocket(sslopt=ssl_cert_off)

    try:
        ws.connect(
            'wss://{address}/ControlApi/socket.io/?EIO=3&transport=websocket'.format(
                address=addr))
    except ws_exception.WebSocketBadStatusException:
        return
    except Exception:
        return

    ws.send('421["request",{"service":"DocsService","method":"getVersion","payload":{}}]')

    while True:
        message = ws.recv()
        if not message:
            return
        if 'gluware_version' in message:
            break

    json_string = message[4:-1]
    json_payload = loads(json_string)['payload']
    payload = loads(json_payload)
    return payload['gluware_version']['semver']
