import requests, urllib, traceback, json, time, socket, sys, subprocess, os
import asyncio, aiohttp, functools, logging, typing, copy
from datetime import datetime, timedelta
from jsonc_parser.parser import JsoncParser
from typing import List
from logging.handlers import TimedRotatingFileHandler
from tabulate import tabulate
from mergedeep import merge
import ipaddress

logging.getLogger("asyncio").setLevel(logging.INFO)

######################
### Set up logging ###
######################
formatter = logging.Formatter('[%(asctime)s][%(filename)s:%(lineno)04d][%(levelname)-4s] %(message)s')
logging.addLevelName(logging.DEBUG, 'DBG')
logging.addLevelName(logging.WARNING, 'WARN')
logging.addLevelName(logging.ERROR, 'ERR')
logging.addLevelName(logging.CRITICAL, 'CRIT')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
file_handler = TimedRotatingFileHandler('tasmota_configurator.log', when="midnight", interval=1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class Template:
    def __init__( self, client, template_path ):
        self.client = client
        self.name: str = os.path.splitext(os.path.basename(template_path))[0]
        try:
            with open(template_path, 'r') as fp:
                self.config = json.load(fp) 
        except:
            self.config = {}
            logging.error("Error loading template %s:\n", template_path, exc_info=True)
    
    @property
    def valid( self ):
        return bool( self.config != {} )
            
class Device:
    def __init__( self, client, deviceDict ):
        self.client = client
        self.ip: str = deviceDict['ip']
        self.enabled: bool = deviceDict['enabled']
        self.template: Template = self.client.get_template( deviceDict['template_name'] )
        self.vars: dict = deviceDict['vars']
        self.name: str = self.vars.get("device_name")
        self.hostname: str = self.vars.get("host_name")
        self.devgroup: str = self.vars.get("devgroup_name")
        self.rules: dict = deviceDict.get("rules", {})
        self.extra_grouptopics: list = deviceDict.get("extra_grouptopics", [])
        self.overrides: dict = deviceDict.get('config_overrides', {})
        self.config: dict = {}
        self.config_filepath: str = None 
        self.generate_config()
    
    @property
    def valid( self ):
        return bool( self.enabled and self.template is not None and self.template.valid )

    def generate_config( self ) -> bool:
        if not self.valid: return False
        # Apply the device's vars
        config = copy.deepcopy(self.template.config)        
        config['device_group_topic'][0] = self.devgroup
        config['devicename'] = self.name
        config['hostname'] = self.hostname
        names = [ self.name ]
        while len(names) < len(config['friendlyname']): names.append("")
        config['friendlyname'] = names
        # Merge any extra grouptopics into the template
        if len(self.extra_grouptopics) > 0:
            grouptopics = ( self.extra_grouptopics 
                + [ self.template.config['mqtt_grptopic'] ] 
                + self.template.config['mqtt_grptopic2'] )
            config['mqtt_grptopic'] = grouptopics[0]
            del grouptopics[0]
            while len(grouptopics) > 3:
                del grouptopics[-1]
            config['mqtt_grptopic2'] = grouptopics
        # Enable and overwrite any rules defined at the device level
        for key in self.rules.keys():
            ruleIdx = int(key[-1])-1
            config['rule_enabled'][key] = 1
            config['rules'][ruleIdx] = self.rules[key]        
        # Merge the device's overrides into the config, and store the config
        self.config = merge({}, config, self.overrides )        
        return True

    async def save_config( self ) -> bool:
        if not self.valid or self.config == {}:
            return False
        self.config_filepath = os.path.join(self.client.device_dir, "%s.json" % self.ip)
        with open(self.config_filepath, 'w') as f:
            json.dump( self.config, f, indent=4 )
        return True

    async def apply_config( self ) -> dict:                
        if not await self.save_config(): 
            return { "ip": self.ip, "hostname": self.hostname, "success": False, "details": "aborted - failed to save config" }
        logging.info("Applying config JSON for %s to %s...", self.name, self.ip )
        args = [ 'python3', 'decode-config.py', '--no-extension', '-s', self.ip, '--restore-file', self.config_filepath ]
        logging.debug("Executing: %s", " ".join(args))
        output = await self.client.run_blocking( subprocess.run, args, capture_output=True, text=True )
        output = output.stderr if output.stdout == '' else output.stdout        
        results = " ".join( output.split("\n")[1:])
        success = bool( "Restore successful" in results )
        return { "ip": self.ip, "hostname": self.hostname, "success": success, "details": results }

    async def is_online( self ) -> bool:
        return await self.client.host_online(self.ip)

    async def query_devgroups( self ) -> dict:
        retval = {'device': self, 'devgroups': [] }
        retval['online'] = await self.is_online()
        if not retval['online']: return retval
        groupnames = await self.client.webcommand( self.ip, "DevGroupName")
        for gn in groupnames.keys():
            if groupnames[gn] != "":
                devgroup = await self.client.webcommand( self.ip, gn.replace("Name", "Status"))
                if 'DevGroupStatus' in devgroup: 
                    retval['devgroups'].append( devgroup['DevGroupStatus'] )        
        return retval        
    
class TasmoUtil:
    def __init__(self, **kwargs):
        self.args = kwargs.get("args")
        self.listed_devices: list = kwargs.get("devices")        
        self.template_dir = os.path.join( os.getcwd(), "template_configs")
        self.device_dir = os.path.join( os.getcwd(), "device_configs")
        self.templates: List[Template] = []
        for filename in os.listdir(self.template_dir):
            if os.path.splitext(filename)[-1].lower() == '.json':
                self.templates.append( 
                    Template(self, os.path.join(self.template_dir, filename) )
                ) 
        self.devices: List[Device] = []
        for d in self.listed_devices:
            self.devices.append( Device( self, d ) )
        self.selected_devices: List[Device] = []

        self.restart_delay = kwargs.get("restart_delay", 15)
        self.reset_delay = kwargs.get("reset_delay", 30)
        self.upgrade_delay = kwargs.get("upgrade_delay", 60)
        self.max_retries = kwargs.get("max_retries", 5)
        self.num_threads = kwargs.get("num_threads", 4)
        self.command_delay = kwargs.get("seconds_between_commands", 15)

        self.cmdline = {
            'scan': {
                'desc': 'Scan your network for devices, fetch their current configurations, and pre-populate your devices.jsonc'
                , 'func': self.scan_devices
            }, 'backup': {
                'desc': 'Fetch configurations for all devices listed in devices.jsonc using decode-config'
                , 'func': self.fetch_device_configs
            }, 'deploy': {
                'desc': 'Deploy configuration(s) to the device(s) of your choice'
                , 'func': self.deploy_devices
            }, 'command': {
                'desc': 'Run a command against multiple devices at once'
                , 'func': self.multi_command
            }, 'devgroups': {
                'desc': 'Queries device group status for devices in devices.jsonc'
                , 'func': self.query_devgroups
            }
        }
        asyncio.run( self.run() )

    async def run( self ):
        if len(self.args) == 1:
            await self.print_command_syntax("Missing argument.")
        elif self.args[1] in self.cmdline.keys():
            await self.cmdline[self.args[1]]['func']()
        else:
            await self.print_command_syntax("Invalid argument.")
    
    async def print_command_syntax( self, message=None ):
        if message: print(message)
        print("Usage:")
        for switch in self.cmdline:
            print("%s %s\n\t%s" % ( os.path.basename(__file__), switch, self.cmdline[switch]['desc'] ) )

    def input( self, message: str ) -> str: 
        return input( "%s%s%s" % ( '\033[96m', message, '\033[0m' ) )    

    def get_template(self, template_name: str) -> Template:
        for t in self.templates:
            if t.name == template_name:
                return t
        return None

    def get_device(self, ip: str ) -> Device:
        for d in self.devices:
            if d.ip == ip and d.enabled:
                return d
        return None

    def print_device_list( self ):
        indexes = []
        for i in range(len(self.devices)):
            indexes.append("[%s] %s (%s)" % ( i, self.devices[i].hostname, self.devices[i].ip))
        indexes.append("[%s] All devices" % len(self.devices) )
        data = indexes.copy()
        if len(data)%2 > 0:
            data.append("")
        count = int(len(data)/2)
        left = list(data[:count])
        right = list(data[count:])
        for i in range(count):
            print( "%s%s" % (left[i].ljust(45, " "), right[i].ljust(45, " ") ) )

    def get_device_selection( self ) -> List[Device]:
        devices = []
        self.print_device_list()
        idx = ""
        while True:
            idx = self.input("Select a device, or enter 'done': ")
            if idx == 'done':
                break
            # If the "all devices" option is picked, return all devices
            if int(idx) == len(self.devices):
                return self.devices
            devices.append(self.devices[int(idx)])
        return devices

    def get_network_ip_selection( self ) -> list:
        cidr = self.input("Enter the subnet of your Tasmota devices (e.g., '192.168.1.0/24'): ")
        try:
            net = ipaddress.IPv4Network(cidr)
            return [str(ip) for ip in net]
        except:
            print("Invalid subnet, try again.")
            return self.get_network_ip_selection()

    async def gather_tasks(self, *tasks):
        semaphore = asyncio.Semaphore(self.num_threads)
        async def sem_task(task):
            async with semaphore:
                return await task
        return await asyncio.gather(*(sem_task(task) for task in tasks), return_exceptions=True)

    async def run_blocking(self, blocking_func: typing.Callable, *args, **kwargs) -> typing.Any:
        """Runs a blocking function in a non-blocking way"""
        func = functools.partial(blocking_func, *args, **kwargs) # `run_in_executor` doesn't support kwargs, `functools.partial` does
        return await asyncio.get_event_loop().run_in_executor(None, func)

    async def host_online( self, ip: str ) -> bool:
        return await self.run_blocking( self.host_online_synch, ip )

    def host_online_synch( self, ip: str) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((ip, 80))
            retval=True
        except:
            retval=False
        s.close() 
        return retval

    async def webcommand( self, ip: str, command: str, retry_count = 0) -> dict:
        if retry_count > self.max_retries:
            raise Exception("Failed to send command %s to %s after 5 retries" % ( command, ip ) )
        url = "http://%s/cm?cmnd=%s" % ( ip, urllib.parse.quote_plus(command) )
        conn = aiohttp.TCPConnector( family=socket.AF_INET, ssl=False )
        try:
            async with aiohttp.ClientSession(connector=conn) as session:
                async with session.get(url) as resp:
                    return await resp.json()
        except json.decoder.JSONDecodeError:
            # Kludge for the 1/60 tasmota devices I have that returns malformed JSON for the `DevGroupStatus` command
            # For shame!
            jsonStr = await resp.text()
            return json.loads("%s}" % jsonStr)
        except ( 
            requests.exceptions.ConnectionError
            , requests.exceptions.ReadTimeout
            , socket.timeout 
            , asyncio.exceptions.TimeoutError
            , aiohttp.client_exceptions.ClientOSError
            , aiohttp.client_exceptions.ServerDisconnectedError
            , aiohttp.client_exceptions.ClientConnectorError
        ):
            logging.debug(" Request to %s failed after 10 seconds (retry=%s), retrying...", url, retry_count )
            return await self.webcommand( ip, command, retry_count+1 )

    async def deploy_devices( self ):
        tasks = []
        for d in self.get_device_selection():
            tasks.append( d.apply_config() )
        data = await self.gather_tasks(*tasks)
        print(tabulate([x.values() for x in data], data[0].keys()))

    async def fetch_device_configs( self ):
        tasks = []
        for d in self.devices:
            tasks.append( self.export_config( d.ip ) )
        data = await self.gather_tasks(*tasks)
        print(tabulate([x.values() for x in data], data[0].keys()))
    
    async def export_config( self, ip: str ) -> dict:
        """ Exports the device's *current* configuration using decode-config """
        if not await self.host_online(ip):
            return {'ip': ip, 'success': False, 'details':"Device is offline"}
        json_path = os.path.join( self.device_dir, "%s.json" % ip )
        logging.debug("Exporting device config JSON for %s to %s...", ip, json_path )        
        args = [ 'python3', 'decode-config.py', '-s', ip, '--json-indent', '4', '-t', 'json', '--no-extension', '-o', json_path ]
        logging.debug("Executing: %s", " ".join(args))
        output = await self.run_blocking( subprocess.run, args, capture_output=True, text=True )
        output = output.stderr if output.stdout == '' else output.stdout        
        results = " ".join( output.split("\n")[1:])
        success = bool( "Backup successful" in results )
        return {'ip': ip, 'success': success, 'details': results}

    async def scan_device( self, ip: str ) -> dict:
        # Don't bother if the host is offline
        if not await self.host_online( ip ):
            logging.debug("%s is offline", ip)
            return {'success': False, 'ip': ip, 'error': 'Offline'}
        
        # Run "Status 0" web command to get device/host names / confirm it is a tasmota device
        try:
            status = await self.webcommand(ip, "Status 0")
        except:
            logging.debug("%s is not a tasmota device.", ip)
            return {'success': False, 'ip': ip, 'error': 'Not tasmota'}
        if 'Status' in status and 'DeviceName' in status['Status']:
            name = status['Status']['DeviceName']
        else: name = '(unknown)'
        if 'StatusNET' in status and 'Hostname' in status['StatusNET']:
            hostname = status['StatusNET']['Hostname']
        else: hostname = '(unknown)'
        config_stub = '\n\t{\n\t\t"ip": "%s",\n\t\t"enabled": false, /* Set this to true once configured */\n\t\t"template_name": "", /* set this to a filename in the template_configs directory, without the .json extension */\n\t\t"vars": {\n\t\t\t"device_name": "%s",\n\t\t\t"host_name": "%s",\n\t\t\t"devgroup_name": "" /* Leave this blank if not using device groups */\n\t\t},\n\t\t"extra_grouptopics": [ /* (optional) Extra GroupTopics - See devices.jsonc.example for details. */\n\t\t\t"office_lights"\n\t\t]\n\t\t"rules": {\n\t\t\t/* (optional) Device-specific rules - See devices.jsonc.example for details. */\n\t\t},\n\t\t"config_overrides": {\n\t\t\t/* (optional) Device-specific configuration overrides - See devices.jsonc.example for details. */\n\t\t}\n\t}' % ( ip, name, hostname )
        # Export the device's current configuration
        export = await self.export_config( ip )

        return {
            'success': True
            , 'ip': ip
            , 'name': name
            , 'hostname': hostname
            , 'config_stub': config_stub
            , 'config_exported': export['success']
        }

    async def scan_missing_devices( self ):
        ips = self.get_network_ip_selection()
        print("Scanning %s to %s..." % ( ips[0], ips[-1]))
        tasks = []
        for ip in ips:
            tasks.append( self.scan_device( ip ) )
        data = await self.gather_tasks(*tasks)
        
        for dev in list(data):
            # Drop known devices from the list
            if dev['ip'] in [x.ip for x in self.devices]:
                data.remove(dev)
            # Drop offline/non-Tasmota devices from the list
            elif not dev['success']:
                data.remove(dev)
        if len(data) > 0:
            # Sort by IP
            data.sort(key = lambda x: [int(y) for y in x['ip'].split('.')] )
            print("\nAdd to your devices.jsonc file:\n%s\n" % ",".join([x['config_stub'] for x in data]) )
            for i in range(len(data)):
                del data[i]['config_stub']
            print(tabulate([x.values() for x in data], data[0].keys()))
        else:
            print("Scan did not find any new devices.")
        return

    async def scan_devices( self ):
        self.max_retries = 1
        if len(self.devices) != 0:
            print("devices.jsonc is already populated. Scanning only for missing devices...")
            await self.scan_missing_devices()
            return        
        ips = self.get_network_ip_selection()
        print("Scanning %s to %s..." % ( ips[0], ips[-1]))
        tasks = []
        for ip in ips:
            tasks.append( self.scan_device( ip ) )
        data = await self.gather_tasks(*tasks)
        # Drop offline/non-Tasmota devices from the list
        for dev in list(data):
            if not dev['success']:
                data.remove(dev)
        # Sort by IP
        data.sort(key = lambda x: [int(y) for y in x['ip'].split('.')] )
        # combine the config stubs for devices.jsonc
        filepath = os.path.join(os.getcwd(), "devices.jsonc")
        with open(filepath, 'w') as f:
            f.write("[\n%s\n]" % ",".join([x['config_stub'] for x in data]))
        for i in range(len(data)):
            del data[i]['config_stub']
        
        print(tabulate([x.values() for x in data], data[0].keys()))
        return

    async def query_devgroups( self ):
        tasks = []
        for d in self.devices:
            tasks.append( d.query_devgroups() )
        data = await self.gather_tasks(*tasks)
        
        devgroups = {}
        for d in data:
            if not d['online']: 
                continue
            for dg in d['devgroups']:
                groupName = dg['GroupName']
                if groupName not in devgroups.keys():
                    devgroups[groupName] = { 'devices': {} }
                ip = d['device'].ip
                devgroups[groupName]['devices'][ip] = { "MessageSeq": dg['MessageSeq'], "Members": dg['Members'] }
        results = []
        for dgName in devgroups.keys():
            devgroups[dgName]['mismatches'] = 0
            deviceCount = len(devgroups[dgName]['devices'].keys())
            for ip in devgroups[dgName]['devices'].keys():
                deviceMemberCount = len(devgroups[dgName]['devices'][ip]['Members'])
                if deviceMemberCount != deviceCount-1:
                    devgroups[dgName]['mismatches'] += 1
                    for ip in devgroups[dgName]['devices'].keys():
                        if ip not in [ x['IPAddress'] for x in devgroups[dgName]['devices'][ip]['Members'] ]:
                            if 'MissingMembers' not in devgroups[dgName]['devices'][ip]:
                                devgroups[dgName]['devices'][ip]['MissingMembers'] = []
                            devgroups[dgName]['devices'][ip]['MissingMembers'].append( ip )

            results.append( {'Group': dgName, 'MemberCount': deviceCount, 'Mismatches': devgroups[dgName]['mismatches']})                    
            for ip in devgroups[dgName]['devices'].keys():
                d = devgroups[dgName]['devices'][ip]
                if 'MissingMembers' in d.keys():
                    for m in d['MissingMembers']:
                        device = self.get_device( ip )
                        missing = self.get_device( m )
                        print("Group '%s': %s does not see %s." % ( dgName, device.hostname, missing.hostname ) )
                    
        print(tabulate([x.values() for x in results], results[0].keys()))        

    async def multi_command_single( self, device: Device, cmd: str ) -> dict:
        retval = { 'ip': device.ip, 'hostname': device.hostname }
        if not await self.host_online( device.ip ):
            print("Device %s (%s) is offline; skipping." % ( device.hostname, device.ip) )
            return None
        data = await self.webcommand( device.ip, cmd )
        if isinstance(data, Exception):
            print("Device %s (%s) did not respond to command '%s'; skipping." % ( device.hostname, device.ip, cmd))
            return None
        return merge(retval, data)

    async def multi_command( self ):
        cmd = self.input("Enter a command to run against one or more devices: ")
        tasks = []
        for d in self.get_device_selection():
            tasks.append(self.multi_command_single( d, cmd ) )
        print("Awaiting %s web command tasks..." % len(tasks))
        data = await self.gather_tasks(*tasks)
        for d in list(data):
            if d is None:
                data.remove(d)
        print(tabulate([x.values() for x in data], data[0].keys()))


if __name__ == '__main__':
    start = datetime.now()
    try:
        devices = JsoncParser.parse_file("./devices.jsonc")
    except:
        devices = []

    TasmoUtil( 
        devices = devices
        , restart_delay = 10
        , reset_delay = 15
        , upgrade_delay = 30
        , max_retries = 5
        , num_threads = 32
        , seconds_between_commands = 0
        , args = sys.argv
    )
    
    end = datetime.now()
    print("Script completed in %s seconds." % (end-start).total_seconds())
        
