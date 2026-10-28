#!/usr/bin/env python3
"""Check libnm's empty-DNS omission offline, without contacting NetworkManager."""
import socket
import uuid

import gi

gi.require_version('NM', '1.0')
from gi.repository import NM


def normalized(with_dns):
    connection = NM.SimpleConnection.new()
    identity = NM.SettingConnection.new()
    identity.props.id = 'Offline Guest Hole DNS regression'
    identity.props.uuid = str(uuid.uuid4())
    identity.props.type = 'vpn'
    identity.props.autoconnect = False
    connection.add_setting(identity)
    vpn = NM.SettingVpn.new()
    vpn.props.service_type = 'org.freedesktop.NetworkManager.protun'
    connection.add_setting(vpn)
    ipv4 = NM.SettingIP4Config.new()
    ipv4.props.method = 'manual'
    ipv4.props.ignore_auto_dns = True
    ipv4.add_address(NM.IPAddress.new(socket.AF_INET, '10.2.0.2', 32))
    if with_dns:
        ipv4.add_dns('10.2.0.1')
    connection.add_setting(ipv4)
    ipv6 = NM.SettingIP6Config.new()
    ipv6.props.method = 'disabled'
    connection.add_setting(ipv6)
    connection.normalize()
    return connection.to_dbus(NM.ConnectionSerializationFlags.ALL).unpack()['ipv4']


empty = normalized(False)
assert not empty.get('dns') and not empty.get('dns-data')
nonempty = normalized(True)
assert nonempty.get('dns-data') == ['10.2.0.1'] or nonempty.get('dns')
print('Offline libnm DNS normalization regression: PASS (no connection activated)')
