"""Listen to the SOC backend WebSocket at ws://127.0.0.1:8000/ws."""

import asyncio
import sys

import websockets
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

WS_URL = "ws://127.0.0.1:8000/ws"


async def listen() -> None:
    print(f"Connecting to {WS_URL} ...")
    try:
        async with websockets.connect(WS_URL) as websocket:
            print("SUCCESS: WebSocket connection established.")
            print("Listening for messages. Press Ctrl+C to exit.\n")
            async for message in websocket:
                print("--- received message ---")
                print(message)
                print("------------------------\n")
    except ConnectionClosed as exc:
        print(
            f"DISCONNECTED: the server closed the WebSocket "
            f"(code={exc.code}, reason={exc.reason or 'none'})."
        )
    except (ConnectionRefusedError, OSError) as exc:
        print(
            "ERROR: could not connect to the WebSocket server.\n"
            f"  URL: {WS_URL}\n"
            f"  Details: {exc}\n"
            "  Is uvicorn running?  uvicorn main:app --host 127.0.0.1 --port 8000"
        )
        sys.exit(1)
    except (InvalidHandshake, InvalidURI, TimeoutError) as exc:
        print(f"ERROR: WebSocket handshake failed: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: unexpected WebSocket failure: {type(exc).__name__}: {exc}")
        sys.exit(1)


def main() -> None:
    try:
        asyncio.run(listen())
    except KeyboardInterrupt:
        print("\nStopped by user. Connection closed.")


if __name__ == "__main__":
    main()
