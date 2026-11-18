#!/usr/bin/env python3
"""Exercise the Swift transport against a real local sing-box instance."""
import json
import pathlib
import socket
import subprocess
import threading
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build'
BUILD.mkdir(exist_ok=True)
SING_BOX = shutil.which('sing-box')
if not SING_BOX:
    raise SystemExit('Install sing-box before running tests: brew install sing-box')

def echo_tcp(server):
    connection, _ = server.accept()
    with connection:
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
        connection.sendall(b''.join(chunks))

def echo_udp(server):
    for _ in range(3):
        packet, address = server.recvfrom(65535)
        server.sendto(packet, address)

with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as reservation:
    for server in [tcp, udp, reservation]:
        server.bind(('127.0.0.1', 0))
    tcp.listen()
    proxy_port = reservation.getsockname()[1]
    reservation.close()
    config = BUILD / 'test-sing-box.json'
    config.write_text(json.dumps({'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': proxy_port}], 'outbounds': [{'type': 'direct'}]}))
    binary = BUILD / 'ProxyTests'
    subprocess.run(['xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library', *map(str, sorted((ROOT / 'Shared').glob('*.swift'))), str(ROOT / 'Tests/ProxyTests.swift'), '-o', str(binary)], check=True)
    with (BUILD / 'test-sing-box.log').open('w') as log:
        proxy = subprocess.Popen([SING_BOX, 'run', '-c', str(config)], stdout=log, stderr=log)
        try:
            import time
            for _ in range(100):
                if proxy.poll() is not None:
                    raise RuntimeError('Test proxy exited; inspect .build/test-sing-box.log')
                try:
                    with socket.create_connection(('127.0.0.1', proxy_port), .1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Test proxy did not start')
            threading.Thread(target=echo_tcp, args=(tcp,), daemon=True).start()
            threading.Thread(target=echo_udp, args=(udp,), daemon=True).start()
            subprocess.run([str(binary), str(proxy_port), str(tcp.getsockname()[1]), str(udp.getsockname()[1])], check=True, timeout=30)
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)
