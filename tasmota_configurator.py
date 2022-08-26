import requests, urllib, traceback, json, time, socket, sys
from datetime import datetime, timedelta
from jsonc_parser.parser import JsoncParser

class TasmotaConfigurator:
    def __init__(self):
        self.HEADER = '\033[95m'
        self.OKBLUE = '\033[94m'
        self.OKCYAN = '\033[96m'
        self.OKGREEN = '\033[92m'
        self.WARNING = '\033[93m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.templates = JsoncParser.parse_file("./templates.jsonc")

    def webcommand(self, ip: str, command: str, retry_count = 0) -> dict:
        if retry_count > 5:
            raise Exception("Failed to send command %s to %s after 5 retries" % ( command, ip ) )
        url = "http://%s/cm?cmnd=%s" % ( ip, urllib.parse.quote_plus(command) )
        try:
            r = requests.get(url, timeout=10)
            return r.json()
        except requests.exceptions.ConnectionError:
            self.logWarn(" Request to %s failed after 10 seconds (retry=%s), retrying..." % ( url, retry_count ) )
            return self.webcommand( ip, command, retry_count+1 )
        except requests.exceptions.ReadTimeout:
            self.logWarn(" Request to %s failed after 10 seconds (retry=%s), retrying..." % ( url, retry_count ) )
            return self.webcommand( ip, command, retry_count+1 )
        except socket.timeout:
            self.logWarn(" Request to %s failed after 10 seconds (retry=%s), retrying..." % ( url, retry_count ) )
            return self.webcommand( ip, command, retry_count+1 )
        except:
            print(self.fmtError(traceback.format_exc()))
            return self.webcommand( ip, command, retry_count+1 )
    
    def config_single_interactive( self ) -> dict:
        self.logHead("\n---------------------------------------------------------")
        self.logHead("-----------  Tasmota Configuration Generator  -----------")
        self.logHead("---------------------------------------------------------\n")
        for i in range(len(self.templates)):
            print("[%s] %s" % (self.fmtInput(i), self.templates[i]['name']))
        templateIdx = input(self.fmtInput("\nEnter the type of device to configure: "))
        template = self.templates[int(templateIdx)].copy()
        
        ip = input(self.fmtInput("\nEnter device's IP Address: "))
        
        self.logSend("Connecting to %s..." % ip)
        resp = self.webcommand(ip, "friendlyname")
        if "Command" in resp:
            return { "success": False, "error": self.fmtError("Device did not recognize FriendlyName command. Is it running a Minimal firmware?") }
        self.logRecv("Connected to %s (%s).\n" % ( ip, resp['FriendlyName1'] ) )

        for var in template['vars']:
            find = var['name']
            repl = input(self.fmtInput(var['prompt']))
            for i in range(len(template['commands'])):
                template['commands'][i] = template['commands'][i].replace(find, repl)

        self.logHead("\n---------------------------------------------------------\n")

        retry_commands = []
        input(self.fmtInput("Press Enter to send the configuration (%s commands), or CTRL+C to cancel. " % len(template['commands'])))
        for c in template['commands']:
            self.logSend("Sending command: %s" % c)
            resp = self.webcommand(ip, c)
            if 'Command' in resp and resp['Command'] == 'Unknown':
                self.logWarn("   Device did not recognize command %s; will retry later." % c)
                retry_commands.append(c)
            self.logRecv(" Response: %s" % json.dumps(resp) )
            if "Restart" in resp.keys():
                self.logBold("Waiting 15s for device to reboot...")
                time.sleep(15)
            elif "Reset" in resp.keys():
                self.logBold("Waiting 15s for device to reset...")
                time.sleep(15)
            
        while( len(retry_commands) > 0 ):
            commands = retry_commands.copy()
            retry_commands = []
            retry_successes = 0
            for c in commands:
                self.logSend("Re-sending command: %s" % c)
                resp = self.webcommand(ip, c)
                if 'Command' in resp and resp['Command'] == 'Unknown':
                    self.logWarn("   Device still did not recognize command %s; will retry later." % c)
                    retry_commands.append(c)
                else:
                    retry_successes += 1
                    self.logRecv(" Response: %s" % json.dumps(resp) )
                    self.webcommand(ip, "Restart 1")
                    self.logBold("Waiting 15s for device to reboot...")
                    time.sleep(15)
            if retry_successes == 0:
                return { "success": False, "error": fmtError("Error: unable to run the following commands:\n%s" % "\n".join(retry_commands)) }

        self.logBold("Done!")
        return { "success": True }
    
    def logSend( self, message: str ): print("%s%s%s" % ( self.OKGREEN, message, self.ENDC ) )
    def logRecv( self, message: str ): print("%s%s%s" % ( self.OKBLUE, message, self.ENDC ) )
    def logWarn( self, message: str ): print("%s%s%s" % ( self.WARNING, message, self.ENDC ) )
    def logHead( self, message: str ): print("%s%s%s" % ( self.HEADER, message, self.ENDC ) )
    def logBold( self, message: str ): print("%s%s%s" % ( self.BOLD, message, self.ENDC ) )
    def fmtInput( self, message: str ) -> str: return "%s%s%s" % ( self.OKCYAN, message, self.ENDC )
    def fmtError( self, message: str ) -> str: return "%s%s%s" % ( self.FAIL, message, self.ENDC )
    
TasmotaConfigurator().config_single_interactive()
