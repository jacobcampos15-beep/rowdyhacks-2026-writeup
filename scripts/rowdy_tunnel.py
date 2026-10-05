#!/usr/bin/env python3
"""Local TCP-to-WSS adapter for the RowdyHacks Erlang challenge."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import os
import ssl
import struct


WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    first, second = await reader.readexactly(2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if second & 0x80 else None
    payload = await reader.readexactly(length)
    if mask:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return opcode, payload


async def send_ws_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes) -> None:
    mask = os.urandom(4)
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", length))
    masked = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    writer.write(bytes(header) + mask + masked)
    await writer.drain()


async def open_websocket(
    host: str, path: str, port: int, use_tls: bool
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    context = ssl.create_default_context() if use_tls else None
    reader, writer = await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname=host if use_tls else None,
    )
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    writer.write(request.encode("ascii"))
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    lines = response.decode("iso-8859-1").split("\r\n")
    if " 101 " not in lines[0]:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"tunnel upgrade failed: {lines[0]}")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()
    if headers.get("sec-websocket-accept") != expected:
        raise ConnectionError("invalid WebSocket handshake")
    return reader, writer


async def bridge(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    host: str,
    path: str,
    port: int,
    use_tls: bool,
) -> None:
    peer = local_writer.get_extra_info("peername")
    try:
        ws_reader, ws_writer = await open_websocket(host, path, port, use_tls)
        print(f"challenge connection opened for {peer}")

        async def local_to_ws() -> None:
            while True:
                payload = await local_reader.read(65536)
                if not payload:
                    return
                await send_ws_frame(ws_writer, 0x2, payload)

        async def ws_to_local() -> None:
            while True:
                opcode, payload = await read_ws_frame(ws_reader)
                if opcode == 0x8:
                    return
                if opcode == 0x9:
                    await send_ws_frame(ws_writer, 0xA, payload)
                    continue
                if opcode == 0x2:
                    local_writer.write(payload)
                    await local_writer.drain()

        tasks = {asyncio.create_task(local_to_ws()), asyncio.create_task(ws_to_local())}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
        ws_writer.close()
        await ws_writer.wait_closed()
    except Exception as error:
        print(f"tunnel error: {error}")
    finally:
        local_writer.close()
        await local_writer.wait_closed()
        print(f"challenge connection closed for {peer}")


async def main_async(args: argparse.Namespace) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: bridge(
            reader, writer, args.host, args.path, args.port, not args.no_tls
        ),
        args.listen_host,
        args.listen_port,
    )
    print(f"Rowdy tunnel ready on {args.listen_host}:{args.listen_port}")
    print(f"Leave this running and point the exploit at {args.listen_host}:{args.listen_port}")
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="RowdyHacks HTTPS tunnel")
    parser.add_argument("--host", default="<TARGET>")
    parser.add_argument("--path", default="/tunnel")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--no-tls", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=2222)
    asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    main()
