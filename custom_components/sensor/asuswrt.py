"""
Support for ASUSWRT routers.
# Version: 0.06
# Author:  Mirukuteii
# Created: 2018-5-13
"""

import logging
import datetime
from datetime import timedelta

from homeassistant.components.sensor import PLATFORM_SCHEMA
import voluptuous as vol
import homeassistant.helpers.config_validation as cv
from homeassistant.const import (
    CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PORT,
    CONF_PROTOCOL, TEMP_CELSIUS, TEMP_FAHRENHEIT, EVENT_HOMEASSISTANT_START)

from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity import generate_entity_id
from homeassistant.util import Throttle

import re
import socket
import telnetlib

REQUIREMENTS = ['pexpect==4.0.1']

_LOGGER = logging.getLogger(__name__)

CONF_PUB_KEY = 'pub_key'
CONF_SSH_KEY = 'ssh_key'
CONF_ROUTER_CONDITIONS = 'router_conditions'
CONF_INTERVAL = 'update_interval'

DEFAULT_SSH_PORT = 22
DEFAULT_INTERVAL = timedelta(minutes=1)
SECRET_GROUP = 'Password or SSH Key'

# condition of sensors
_DEFAULT_COND = {
    'router_name': ['Router Name', None, 'mdi:router-wireless'],
    'router_nowtime': ['Router Nowtime', None, 'mdi:clock'],
    'router_uptime': ['Router Uptime', None, 'mdi:av-timer'],
}
_CPU_COND = {
    'router_cpu_1min_load': ['CPU Load (1 min)', None, 'mdi:select-inverse'],
    'router_cpu_5min_load': ['CPU Load (5 min)', None, 'mdi:select-inverse'],
    'router_cpu_15min_load': ['CPU Load (15 min)', None, 'mdi:select-inverse'],
    'router_cpu_temp': ['CPU Temperature', None, 'mdi:thermometer'],
}
_MEM_COND = {
    'router_mem_used': ['Memory Used', None, 'mdi:memory'],
    'router_mem_free': ['Memory Free', None, 'mdi:memory'],
    'router_mem_shrd': ['Memory Shared', None, 'mdi:memory'],
    'router_mem_buff': ['Memory Buffer', None, 'mdi:memory'],
    'router_mem_cached': ['Memory Cached', None, 'mdi:memory'],
}
_NET_COND = {
    'router_net_mac': ['Router MAC', None, 'mdi:ethernet'],
    'router_net_wan_ip': ['Wan IP', None, 'mdi:ethernet'],
    'router_net_lan_ip': ['Lan IP', None, 'mdi:ethernet'],
    'router_net_wan_downspd': ['Internet Download Speed(AVR)', 'KiB', 'mdi:arrow-down-bold-circle'],
    'router_net_wan_upspd': ['Internet Upload Speed(AVR)', 'KiB', 'mdi:arrow-up-bold-circle'],
}
_WIFI_COND = {
    'router_wifi_24G_temp': ['Chip Temperature(2.4G)', None, 'mdi:thermometer'],
    'router_wifi_5G_temp': ['Chip Temperature(5G)', None, 'mdi:thermometer'],
    'router_wifi_24G_txpwr': ['Transmit Power(2.4G)', 'dBm', 'mdi:signal'],
    'router_wifi_5G_txpwr': ['Transmit Power(5G)', 'dBm', 'mdi:signal'],
    'router_wifi_24G_stalist': ['Sta list(2.4G)', None, 'mdi:wifi'],
    'router_wifi_5G_stalist': ['Sta list(5G)', None, 'mdi:wifi'],
}
_SS_COND = {
    'router_ss_fs': ['Foreign State', None, 'mdi:telegram'],
    'router_ss_cs': ['China State', None, 'mdi:wall'],
}

_ROUTER_CONDITIONS = ['cpu', 'mem', 'net', 'wifi', 'bukemiaoshu']

# command_lines
_CMD_NAME = 'nvram get computer_name'
_CMD_WANIP = 'nvram get wan_ipaddr'
_CMD_LANIP = 'nvram get lan_ipaddr'
_CMD_MAC = 'nvram get lan_hwaddr'
_CMD_UPTIME = 'uptime'
_CMD_CPUTEMP = "cat /proc/dmu/temperature |sed -e 's/[^0-9]//g'"
_CMD_24GTEMP = "wl -i eth1 phy_tempsense |awk '{print $1 / 2 + 20}'"
_CMD_5GTEMP = "wl -i eth2 phy_tempsense |awk '{print $1 / 2 + 20}'"
_CMD_24GTXPWR = 'wl -i eth1 txpwr_target_max'
_CMD_5GTXPWR = 'wl -i eth2 txpwr_target_max'
_CMD_MEM = 'top -n 1 -b |grep ^Mem'
_CMD_PPP0SPD = "cat /proc/net/dev |grep ppp0 |awk '{print $2,$10}'"
_CMD_SSF = 'nvram get ss_foreign_state'
_CMD_SSC = 'nvram get ss_china_state'
_CMD_STALIST = 'wl assoclist'
_CMD_24GSTALIST = 'wl autho_sta_list'
_CMD_5GSTALIST = 'wl -i eth2 autho_sta_list'

#_CMD_RSSI = wl -i eth1 rssi MAC

# regex_rules
_REGEX_NAME = re.compile(
    r'(?P<router_name>(.+))\s+')
_REGEX_WANIP = re.compile(
    r'(?P<router_net_wan_ip>(.+))\s+')
_REGEX_LANIP = re.compile(
    r'(?P<router_net_lan_ip>(.+))\s+')
_REGEX_MAC = re.compile(
    r'(?P<router_net_mac>(.+))\s+')
_REGEX_UPTIME = re.compile(
    r'\s' +
    r'(?P<router_nowtime>(.+))\sup\s' +
    r'(?P<router_uptime>(.+)),\s+load.+:\s' +
    r'(?P<router_cpu_1min_load>(.+)),\s' +
    r'(?P<router_cpu_5min_load>(.+)),\s' +
    r'(?P<router_cpu_15min_load>(.+))\s+')
_REGEX_CPUTEMP = re.compile(
    r'(?P<router_cpu_temp>(\d+))\s+')
_REGEX_24GTEMP = re.compile(
    r'(?P<router_wifi_24G_temp>(\d+))')
_REGEX_5GTEMP = re.compile(
    r'(?P<router_wifi_5G_temp>(\d+))')
_REGEX_24GTXPWR = re.compile(
    r'.+:\s+' +
    r'(?P<router_wifi_24G_txpwr>(\d.+))\s')
_REGEX_5GTXPWR = re.compile(
    r'.+:\s+' +
    r'(?P<router_wifi_5G_txpwr>(\d.+))\s')
_REGEX_MEM = re.compile(
    r'Mem:\s' +
    r'(?P<router_mem_used>(\d+K))\sused,\s' +
    r'(?P<router_mem_free>(\d+K))\sfree,\s' +
    r'(?P<router_mem_shrd>(\d+K))\sshrd,\s' +
    r'(?P<router_mem_buff>(\d+K))\sbuff,\s' +
    r'(?P<router_mem_cached>(\d+K))\s.+')
_REGEX_PPP0SPD = re.compile(
    r'(?P<router_net_ppp0_rx>(.+))\s+' +
    r'(?P<router_net_ppp0_tx>(.+))\s+')
_REGEX_SSF = re.compile(
    r'<.+>' +
    r'(?P<router_ss_fs>(.+))<.+>\s+')
_REGEX_SSC = re.compile(
    r'<.+>' +
    r'(?P<router_ss_cs>(.+))<.+>\s+')
_REGEX_STALIST = re.compile(
    r'\w+\s' +
    r'(?P<mac>(([0-9A-F]{2}[:-]){5}([0-9A-F]{2})))')


PLATFORM_SCHEMA = vol.All(
    cv.has_at_least_one_key(CONF_PASSWORD, CONF_PUB_KEY, CONF_SSH_KEY),
    PLATFORM_SCHEMA.extend({
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_PROTOCOL, default='ssh'): vol.In(['ssh', 'telnet']),
        vol.Optional(CONF_PORT, default=DEFAULT_SSH_PORT): cv.port,
        vol.Optional(CONF_ROUTER_CONDITIONS, default=[]):
            vol.All(cv.ensure_list, [vol.In(_ROUTER_CONDITIONS)]),
        vol.Optional(CONF_INTERVAL, default= DEFAULT_INTERVAL):
            vol.All(cv.time_period, cv.positive_timedelta),
        vol.Exclusive(CONF_PASSWORD, SECRET_GROUP): cv.string,
        vol.Exclusive(CONF_SSH_KEY, SECRET_GROUP): cv.isfile,
        vol.Exclusive(CONF_PUB_KEY, SECRET_GROUP): cv.isfile
    }))

def setup_platform(hass, config, add_devices, discovery_info=None):
    """Set up the ASUSWRT sensors."""
    def run_setup(event):
        """Wait until Home Assistant is fully initialized before creating.
        Delay the setup until Home Assistant is fully initialized.
        This allows any entities to be created already
        """
        host = config.get(CONF_HOST)
        port = config.get(CONF_PORT)
        username = config.get(CONF_USERNAME)
        password = config.get(CONF_PASSWORD, '')
        ssh_key = config.get(CONF_SSH_KEY, config.get(CONF_PUB_KEY, ''))
        protocol = config.get(CONF_PROTOCOL)
        router_conditions = config.get(CONF_ROUTER_CONDITIONS)
        interval = config.get(CONF_INTERVAL)

        if protocol == 'ssh':
            connection = SshConnection(
                host, port, username, password, ssh_key)
        else:
            connection = TelnetConnection(
                host, port, username, password)

        sensors = []
        for key in _DEFAULT_COND:
            sensors += [AsusWrtSensor(hass, connection, key, _DEFAULT_COND[key], interval)]

        if 'cpu' in router_conditions:
            for key in _CPU_COND:
                sensors += [AsusWrtSensor(hass, connection, key, _CPU_COND[key], interval)]

        if 'mem' in router_conditions:
            for key in _MEM_COND:
                sensors += [AsusWrtSensor(hass, connection, key, _MEM_COND[key], interval)]

        if 'net' in router_conditions:
            for key in _NET_COND:
                sensors += [AsusWrtSensor(hass, connection, key, _NET_COND[key], interval)]

        if 'wifi' in router_conditions:
            for key in _WIFI_COND:
                sensors += [AsusWrtSensor(hass, connection, key, _WIFI_COND[key], interval)]

        if 'bukemiaoshu' in router_conditions:
            for key in _SS_COND:
                sensors += [AsusWrtSensor(hass, connection, key, _SS_COND[key], interval)]

        add_devices(sensors, True)

    # Wait until start event is sent to load this component.
    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, run_setup)


class AsusWrtSensor(Entity):
    """Representation of a AsusWrt Sensor."""

    def __init__(self, hass, connection, key, info, interval):
        """Initialize the sensor."""
        self._hass = hass
        self._connection = connection
        self._id = key
        self._name = info[0]
        self._units = info[1]
        self._icon = info[2]
        self._tempunit = hass.config.units.temperature_unit
        self.entity_id = generate_entity_id(
            'sensor.{}', self._id, hass=self._hass)
        self._state = None
        self.attributes = {}
        self._rx = 0
        self._tx = 0
        self._rt = datetime.datetime.now()
        self._tt = datetime.datetime.now()
        self.update = Throttle(interval)(self._update)


    @property
    def name(self):
        """Return the name of the sensor, if any."""
        return self._name

    @property
    def state(self):
        """Return the state of the sensor."""
        return self._state

    @property
    def device_state_attributes(self):
        """Return the state attributes."""
        return self.attributes

    @property
    def icon(self):
        """Icon to use in the frontend, if any."""
        return self._icon

    @property
    def unit_of_measurement(self):
        """Return the unit the value is expressed in."""
        if self._id in ['router_cpu_temp',
                        'router_wifi_24G_temp',
                        'router_wifi_5G_temp']:
            return self._tempunit
        return self._units

    def _update(self):
        """Get the latest data for the states."""
        if self._connection is not None:
            if self._id == 'router_name':
                self._state = get_data_dict(self._connection, _CMD_NAME, _REGEX_NAME).get(self._id)
            elif self._id in ['router_nowtime', 'router_uptime', 'router_cpu_1min_load', 'router_cpu_5min_load', 'router_cpu_15min_load']:
                self._state = get_data_dict(self._connection, _CMD_UPTIME, _REGEX_UPTIME).get(self._id)
            elif self._id == 'router_net_wan_ip':
                self._state = get_data_dict(self._connection, _CMD_WANIP, _REGEX_WANIP).get(self._id)
            elif self._id == 'router_net_lan_ip':
                self._state = get_data_dict(self._connection, _CMD_LANIP, _REGEX_LANIP).get(self._id)
            elif self._id == 'router_net_mac':
                self._state = get_data_dict(self._connection, _CMD_MAC, _REGEX_MAC).get(self._id)
            elif self._id == 'router_cpu_temp':
                self._state = get_data_dict(self._connection, _CMD_CPUTEMP, _REGEX_CPUTEMP).get(self._id)
                self._state = correct_temperature_unit(self._state, self._tempunit)
            elif self._id == 'router_wifi_24G_temp':
                self._state = get_data_dict(self._connection, _CMD_24GTEMP, _REGEX_24GTEMP).get(self._id)
                self._state = correct_temperature_unit(self._state, self._tempunit)
            elif self._id == 'router_wifi_5G_temp':
                self._state = get_data_dict(self._connection, _CMD_5GTEMP, _REGEX_5GTEMP).get(self._id)
                self._state = correct_temperature_unit(self._state, self._tempunit)
            elif self._id == 'router_wifi_24G_txpwr':
                self._state = get_data_dict(self._connection, _CMD_24GTXPWR, _REGEX_24GTXPWR).get(self._id)
            elif self._id == 'router_wifi_5G_txpwr':
                self._state = get_data_dict(self._connection, _CMD_5GTXPWR, _REGEX_5GTXPWR).get(self._id)
            elif self._id == 'router_wifi_24G_stalist':
                stalist = get_data_list(self._connection, _CMD_24GSTALIST, _REGEX_STALIST, 'mac')
                self._state = len(stalist)
                self.attributes['sta_list'] = stalist
            elif self._id == 'router_wifi_5G_stalist':
                stalist = get_data_list(self._connection, _CMD_5GSTALIST, _REGEX_STALIST, 'mac')
                self._state = len(stalist)
                self.attributes['sta_list'] = stalist
            elif self._id in list(_MEM_COND.keys()):
                self._state = get_data_dict(self._connection, _CMD_MEM, _REGEX_MEM).get(self._id)
            elif self._id == 'router_net_wan_downspd':
                rxnow = int(get_data_dict(self._connection, _CMD_PPP0SPD, _REGEX_PPP0SPD).get('router_net_ppp0_rx'))
                rtnow = datetime.datetime.now()
                if self._rx != 0 :
                    drx = rxnow - self._rx
                    if drx <= 0:
                        drx += 4294967296
                    self._state = round((drx/((rtnow-self._rt).seconds)/1024),3)
                    if self._state <= 0 :
                        self.attributes['debug_rx0'] = self._rx
                        self.attributes['debug_rxn'] = rxnow
                        self.attributes['debug_rt0'] = self._rt
                        self.attributes['debug_rtn'] = rtnow
                else:
                    self._state = 'spd init...'
                self._rx = rxnow
                self._rt = rtnow
            elif self._id == 'router_net_wan_upspd':
                txnow = int(get_data_dict(self._connection, _CMD_PPP0SPD, _REGEX_PPP0SPD).get('router_net_ppp0_tx'))
                ttnow = datetime.datetime.now()
                if self._tx != 0 :
                    dtx = txnow - self._tx
                    if dtx <= 0:
                        dtx += 4294967296
                    self._state = round((dtx/((ttnow-self._tt).seconds)/1024),3)
                    if self._state <= 0 :
                        self.attributes['debug_tx0'] = self._tx
                        self.attributes['debug_txn'] = txnow
                        self.attributes['debug_tt0'] = self._tt
                        self.attributes['debug_ttn'] = ttnow
                else:
                    self._state = 'spd init...'
                self._tx = txnow
                self._tt = ttnow
            elif self._id == 'router_ss_fs':
                self._state = get_data_dict(self._connection, _CMD_SSF, _REGEX_SSF).get(self._id)
            elif self._id == 'router_ss_cs':
                self._state = get_data_dict(self._connection, _CMD_SSC, _REGEX_SSC).get(self._id)



class _Connection:
    def __init__(self):
        self._connected = False

    @property
    def connected(self):
        """Return connection state."""
        return self._connected

    def connect(self):
        """Mark current connection state as connected."""
        self._connected = True

    def disconnect(self):
        """Mark current connection state as disconnected."""
        self._connected = False

class SshConnection(_Connection):
    """Maintains an SSH connection to an ASUS-WRT router."""

    def __init__(self, host, port, username, password, ssh_key):
        """Initialize the SSH connection properties."""
        super().__init__()

        self._ssh = None
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._ssh_key = ssh_key

    def run_command(self, command):
        """Run commands through an SSH connection.

        Connect to the SSH server if not currently connected, otherwise
        use the existing connection.
        """
        from pexpect import pxssh, exceptions

        try:
            if not self.connected:
                self.connect()
            self._ssh.sendline(command)
            self._ssh.prompt()
            lines = self._ssh.before.split(b'\n')[1:-1]
            return [line.decode('utf-8') for line in lines]
        except exceptions.EOF as err:
            _LOGGER.error("Connection refused. %s", self._ssh.before)
            self.disconnect()
            return None
        except pxssh.ExceptionPxssh as err:
            _LOGGER.error("Unexpected SSH error: %s", err)
            self.disconnect()
            return None
        except AssertionError as err:
            _LOGGER.error("Connection to router unavailable: %s", err)
            self.disconnect()
            return None

    def connect(self):
        """Connect to the ASUS-WRT SSH server."""
        from pexpect import pxssh

        self._ssh = pxssh.pxssh()
        if self._ssh_key:
            self._ssh.login(self._host, self._username, quiet=False,
                            ssh_key=self._ssh_key, port=self._port)
        else:
            self._ssh.login(self._host, self._username, quiet=False,
                            password=self._password, port=self._port)

        super().connect()

    def disconnect(self):   \
            # pylint: disable=broad-except
        """Disconnect the current SSH connection."""
        try:
            self._ssh.logout()
        except Exception:
            pass
        finally:
            self._ssh = None

        super().disconnect()

class TelnetConnection(_Connection):
    """Maintains a Telnet connection to an ASUS-WRT router."""

    def __init__(self, host, port, username, password):
        """Initialize the Telnet connection properties."""
        super().__init__()

        self._telnet = None
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._prompt_string = None

    def run_command(self, command):
        """Run a command through a Telnet connection.

        Connect to the Telnet server if not currently connected, otherwise
        use the existing connection.
        """
        try:
            if not self.connected:
                self.connect()
            self._telnet.write('{}\n'.format(command).encode('ascii'))
            data = (self._telnet.read_until(self._prompt_string).
                    split(b'\n')[1:-1])
            return [line.decode('utf-8') for line in data]
        except EOFError:
            _LOGGER.error("Unexpected response from router")
            self.disconnect()
            return None
        except ConnectionRefusedError:
            _LOGGER.error("Connection refused by router. Telnet enabled?")
            self.disconnect()
            return None
        except socket.gaierror as exc:
            _LOGGER.error("Socket exception: %s", exc)
            self.disconnect()
            return None
        except OSError as exc:
            _LOGGER.error("OSError: %s", exc)
            self.disconnect()
            return None

    def connect(self):
        """Connect to the ASUS-WRT Telnet server."""
        self._telnet = telnetlib.Telnet(self._host)
        self._telnet.read_until(b'login: ')
        self._telnet.write((self._username + '\n').encode('ascii'))
        self._telnet.read_until(b'Password: ')
        self._telnet.write((self._password + '\n').encode('ascii'))
        self._prompt_string = self._telnet.read_until(b'#').split(b'\n')[-1]

        super().connect()

    def disconnect(self):   \
            # pylint: disable=broad-except
        """Disconnect the current Telnet connection."""
        try:
            self._telnet.write('exit\n'.encode('ascii'))
        except Exception:
            pass

        super().disconnect()

def _parse_lines(lines, regex):
    """Parse the lines using the given regular expression.

    If a line can't be parsed it is logged and skipped in the output.
    """
    results = []
    for line in lines:
        match = regex.search(line)
        if not match:
            _LOGGER.debug("Could not parse row: %s", line)
            continue
        results.append(match.groupdict())
    return results

def get_data_dict(connection, cmd_line, regex_rule):
    lines = connection.run_command(cmd_line)
    if not lines:
        return {}
    result = _parse_lines(lines, regex_rule)
    data = {}
    for element in result:
        data.update(element)
    return data

def get_data_list(connection, cmd_line, regex_rule, key):
    lines = connection.run_command(cmd_line)
    if not lines:
        return {}
    result = _parse_lines(lines, regex_rule)
    data = []
    for element in result:
        data.append(element.get(key).upper())
    return data

def correct_temperature_unit(temp_c,temp_unit):
    if temp_unit == TEMP_CELSIUS:
        return temp_c
    elif temp_unit == TEMP_FAHRENHEIT:
        temp_f = int(float(temp_c)*1.8 + 32)
        return temp_f
    else:
        return temp_c+' Celsius Degrees'
