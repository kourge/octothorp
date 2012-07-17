#!/usr/bin/python

from telnetlib import Telnet
from threading import Thread
import time
import sys
import re
import atexit

try:
    from odict import OrderedDict
except ImportError:
    pass

try:
    dictionary = OrderedDict
except NameError:
    dictionary = dict


class AMIEvent(dictionary):
    def __str__(self):
        if not self:
            return ''
        return '\r\n'.join('%s: %s' % (a, b) for a, b in self.items()) + \
               '\r\n\r\n'

    def __repr__(self):
        return self.__str__()


class AMI(object):

    class ExecutionError(StandardError):
        pass

    def __init__(self, host, port=5038, default_context="default"):
        self.events = []
        self.listeners = {}
        self.debugger = lambda x: sys.stderr.write("\n=> %r\n>>> " % x)
        try:
            self.dict = AMIEvent
        except NameError:
            self.dict = dict

        self.connection = Telnet(host, port)
        self.connection.read_until("\r\n")

        self.default_context = default_context

        atexit.register(lambda: self.logoff())
        self.pump = Thread(None, self.pump_events)
        self.pump.start()

    def __repr__(self):
        fields = ["connection", "pump", "dict", "listeners"]
        fields = map(lambda f: "%s=%r" % (f, getattr(self, f)), fields)
        return "<%s %s>" % (self.__class__.__name__, ", ".join(fields))

    def parse(self, string):
        if string.startswith("Response: Follows"):
            # telnet.read_until preserves the until token
            string = string.replace("--END COMMAND--\r\n\r\n", '')
            sep = string.rindex("\r\n")
            results = string[(sep + 2):].lstrip()
            keys = string[:sep].rstrip()
            keys = map(lambda n: n.split(": "), keys.split("\r\n"))
            resp = map(lambda n: (n[0], ": ".join(n[1:]).strip()), keys)
            resp.append(("Results", results))
        else:
            resp = filter(lambda x: x != '', string.split("\r\n"))
            for k in range(len(resp)):
                x = resp[k].split(": ")
                x = tuple([x[0], ": ".join(x[1:])])
                resp[k] = x
        return self.dict(resp)

    def cmd(self, cmd):
        self.connection.write(cmd + "\r\n\r\n")

    def pump_events(self, until="\r\n\r\n"):
        while True:
            try:
                response = self.parse(self.connection.read_until(until))
            except EOFError:
                break
            self.events.append(response)
            self.dispatch_event(response)
            time.sleep(0.01)

    def dispatch_event(self, e):
        name = e["Event"] if e.has_key("Event") else e["Response"]
        listeners = self.listeners[name] if self.listeners.has_key(name) else []
        if self.listeners.has_key('*'):
            listeners.extend(self.listeners['*'])
        for f in listeners:
            Thread(None, lambda: f(e)).start()

    def attach(self, events, f):
        if not callable(f):
            raise TypeError("%r object is not callable" % type(f).__name__)
        if not isinstance(events, list):
            events = [events]
        for e in events:
            if not self.listeners.has_key(e): self.listeners[e] = []
            self.listeners[e].append(f)

    def detach(self, event, f=None):
        if not self.listeners.has_key(event): return None
        if event and f == None:
            if not self.listeners.has_key(event): return None
            events = self.listeners[event]
            del self.listeners[event]
            return events
        try:
            self.listeners[event].remove(f)
            return f
        except ValueError:
            return None

    def get_debug(self):
        return self._debug

    def set_debug(self, v):
        self._debug = bool(v)
        if self._debug:
            self.attach('*', self.debugger)
        else:
            self.detach('*', self.debugger)

    debug = property(get_debug, set_debug)

    def do_action(self, action, opts={}):
        if not opts.has_key("ActionID") or not opts.has_key("actionID"):
            opts["ActionID"] = "%s-%r" % (action.lower(), time.time())

        vars = "\r\n".join(["%s: %s" % (a.capitalize(), b)
                            for a, b in opts.items()])
        if vars != "": vars = "\r\n" + vars
        self.cmd("Action: " + action.capitalize() + vars)
        return opts["ActionID"]

    def login(self, username, secret, opts={}):
        opts.update({"username": username, "secret": secret})
        return self.do_action("Login", opts)

    def logoff(self):
        return self.do_action("Logoff")

    def ping(self):
        return self.do_action("Ping")

    def call(self, channel, exten, opts={}):
        vars = {
            "channel": channel, "exten": exten, "context": self.default_context,
            "priority": 1, "async": "yes", "timeout": 60 * 1000
        }
        vars.update(opts)
        return self.do_action("Originate", vars)

    def dial(self, channel, keys, interval=0.5):
        for c in keys:
            self.do_action("PlayDTMF", {"channel": channel, "digit": c})
            time.sleep(interval)

    def hangup(self, channel):
        return self.do_action("Hangup", {"channel": channel})

    def transfer(self, channel, exten, opts={}):
        vars = {
            "channel": channel, "exten": exten, "context": self.default_context,
            "priority": 1
        }
        vars.update(opts)
        return self.do_action("Redirect", opts)

    def command(self, cmd):
        return self.do_action("Command", {"command": cmd})

    def execute(self, cmd):
        data = [None]
        def listener(e):
            data[0] = e["Results"]
        def handler(e):
            data[0] = ExecutionError(e["Message"])
        self.attach("Follows", listener)
        self.attach("Error", handler)
        self.command(cmd)
        while data[0] == None:
            time.sleep(0.02)
        self.detach("Error", handler)
        self.detach("Follows", listener)
        return data[0]

class AMICLIProxy(object):

    def __init__(self):
        try:
            self.dict = OrderedDict
        except NameError:
            self.dict = dict

    try:
        dict = AMIEvent
    except NameError:
        dict = dict

    @classmethod
    def crunch_output(cls, incoming, pattern, statistics=None):
        def match_to_dict(match):
            if match == None: return cls.dict()
            plist = []
            d = match.groupdict()
            groups = match.re.groupindex.items()
            for name, i in sorted(groups, lambda a, b: cmp(a[1], b[1])):
                plist.append((name, d[name] if d.has_key(name) else None))
            return cls.dict(plist)

        stats = statistics.search(incoming) if statistics != None else None
        if statistics != None: incoming = statistics.sub('', incoming)

        data = []
        for line in re.split(r"\r?\n", incoming):
            d = match_to_dict(pattern.search(line))
            if len(d) != 0: data.append(d)
        return {"data": data, "stats": match_to_dict(stats)}


class Channel(object):

    class ChannelError(StandardError):
        pass

    def __init__(self, connection, name, info=None):
        self.name = name
        self.connection = connection
        try:
            self._info = OrderedDict()
        except NameError:
            self._info = dict()
        self.first_repr = True
        self.update_info(info)

    def __str__(self):
        return self.name

    @classmethod
    def process_event(cls, event):
        strip = "Event Privilege ActionID Uniqueid".split(' ')
        e = event.copy()
        for k in strip: del e[k]
        channel = e["Channel"]
        del e["Channel"]
        if hasattr(e, "insert"):
            e.insert(0, "Name", channel)
        else:
            e["name"] = channel
        return e

    @classmethod
    def fetch_info(cls, connection, channel=None):
        id = "list-channels-%s" % str(time.time())
        eos = [False]
        events = []
        action_keys = {"actionID": id}
        err_message = [None]
        def listener(e):
            if e.has_key("ActionID") and e["ActionID"] != id: return
            if e.has_key("Event") and e["Event"] == "StatusComplete":
                eos[0] = True
            if e.has_key("Event") and e["Event"] == "Status":
                events.append(cls.process_event(e))
            if e.has_key("Response") and e["Response"] == "Error":
                err_message[0] = e["Message"]
                eos[0] = True
        if channel: action_keys["channel"] = channel
        connection.do_action("Status", action_keys)
        connection.attach('*', listener)
        while eos[0] == False:
            time.sleep(0.05)
        connection.detach('*', listener)
        if err_message[0] != None: raise cls.ChannelError(err_message[0])
        return events if channel == None else events[0]

    @classmethod
    def list(cls, connection):
        return map(lambda x: Channel(connection, x["Name"], x),
                   cls.fetch_info(connection))

    def __repr__(self):
        if self.first_repr:
            self.first_repr = False
        else:
            self.update_info()
        fields = self._info.keys() if len(self._info) != 0 else ["name"]
        fields = map(lambda f: "%s=%r" % (f, getattr(self, f)), fields)
        return "<%s %s>" % (self.__class__.__name__, ", ".join(fields))

    def update_info(self, info=None):
        if not info:
            info = self.__class__.fetch_info(self.connection, self.name)
            self._info.clear()
        for k in info.keys():
            n = re.sub(
                r"([A-Z])([A-Z]*)([A-Z])",
                lambda m: m.group(1) + m.group(2).lower() + m.group(3),
                k)
            n = re.sub(
                r"([a-z])([A-Z])",
                lambda m: m.group(1) + '_' + m.group(2),
                n).lower()
            if n in ["priority", "seconds"] and type(info[k]) != int:
                info[k] = int(info[k], 10)
            self._info[n] = info[k]

    def __getattr__(self, name):
        self.update_info()
        if not self._info.has_key(name):
            raise AttributeError("object has no attribute %r" % name)
        return self._info[name]


    def call(self, *args, **kwargs):
        return self.connection.call(self, *args, **kwargs)

    def dial(self, *args, **kwargs):
        return self.connection.dial(self, *args, **kwargs)

    def hangup(self, *args, **kwargs):
        return self.connection.hangup(self, *args, **kwargs)

    def transfer(self, *args, **kwargs):
        return self.connection.transfer(self, *args, **kwargs)


class Conference(AMICLIProxy):

    pattern = re.compile(r"""
        (?P<number>   \d+)            \s+
        (?P<parties>  0*\d+)          \s+
        (?P<marked>   .+?)            \s+
        (?P<activity> \d\d:\d\d:\d\d) \s+
        (?P<creation> .+?)            \s+
    """, re.X)
    statistics = re.compile(r"""
        Conf\s Num\s+ Parties\s+ Marked\s+ Activity\s+ Creation\s* \n
        |\n
        \*\s Total\s number\s of\s MeetMe\s users:\s (?P<users> \d+)
    """, re.M | re.X)

    participants_p = re.compile(r"""
        User\s \#:\s (?P<user>     \d+)            \s+
                     (?P<exten>    \d+)            \s+
                     (?P<name>     .+?)            \s+
          Channel:\s (?P<channel>  .+?)            \s+
                     (?P<status>   \(.+\))         \s+
                     (?P<duration> \d\d:\d\d:\d\d) \s*
    """, re.X)
    participants_statistics = re.compile(r"""
        (?P<number> \d+)\s users\s in\s that\s conference\.
    """, re.M | re.X)

    def __init__(self, connection, number, info=None):
        super(self.__class__, self).__init__()
        self.connection = connection
        self.number = number
        try:
            self._info = OrderedDict()
        except NameError:
            self._info = dict()

        if not info == None:
            if info.has_key("number"): del info["number"]
            if info.has_key("parties"): info["parties"] = int(info["parties"])
        self.update_info(info)

    def __repr__(self):
        fields = ["number"]
        fields = map(lambda f: "%s=%r" % (f, getattr(self, f)), fields)
        return "<%s %s>" % (self.__class__.__name__, ", ".join(fields))

    @classmethod
    def fetch_info(cls, connection):
        data = connection.execute("meetme")
        if data == "No active MeetMe conferences.":
            return []
        return cls.crunch_output(data, cls.pattern, cls.statistics)["data"]

    @classmethod
    def list(cls, connection):
        results = cls.fetch_info(connection)
        return map(lambda c: Conference(connection, c["number"], c), results)

    def update_info(self, info=None):
        if not info:
            info = filter(lambda x: x["number"] == str(self.number),
                          self.__class__.fetch_info(self.connection))[0]
            self._info.clear()
        if info.has_key("parties"): del info["parties"]
        for k, v in info.items():
            self._info[k] = v

    def __getattr__(self, name):
        self.update_info()
        if not self._info.has_key(name):
            raise AttributeError("object has no attribute %r" % name)
        return self._info[name]

    def execute(self, cmd):
        return self.connection.execute(cmd)

    @property
    def participants(self):
        data = self.execute("meetme list %s" % self.number)
        if data == "No active conferences." or data == None:
            return []
        cls = self.__class__
        return cls.crunch_output(data, cls.participants_p,
                                       cls.participants_statistics)["data"]
    users = participants

    def lock(self):
        return self.execute("meetme lock %s" % self.number)

    def unlock(self):
        return self.execute("meetme unlock %s" % self.number)

    def kick(self, user):
        return self.execute("meetme kick %s %s" % (self.number, user))

    def kick_all(self):
        return self.kick("all")

    def mute(self, user):
        return self.execute("meetme mute %s %s" % (self.number, user))

    def unmute(self, user):
        return self.execute("meetme unmute %s %s" % (self.number, user))


class Extension(object):
    NOT_FOUND = -1
    IDLE = 0
    IN_USE = 1
    BUSY = 2
    UNAVAILABLE = 4
    RINGING = 8
    ON_HOLD = 16

    class ExtensionError(StandardError):
        pass

    def __init__(self, connection, name, context=None):
        self.connection = connection
        self.name = name
        self.context = context

    def __repr__(self):
        fields = ["name", "context"]
        fields = map(lambda f: "%s=%r" % (f, getattr(self, f)), fields)
        return "<%s %s>" % (self.__class__.__name__, ", ".join(fields))

    @property
    def status(self):
        id = None
        eos = [False]
        event = [None]
        action_keys = {"exten": self.name}
        def listener(e):
            if e.has_key("ActionID") and e["ActionID"] == id:
                event[0] = e
                eos[0] = True
        if self.context: action_keys["context"] = self.context
        id = self.connection.do_action("ExtensionState", action_keys)
        self.connection.attach("Success", listener)
        while eos[0] == False:
            time.sleep(0.01)
        self.connection.detach("Success", listener)
        event[0]["Status"] = int(event[0]["Status"])
        if event[0]["Status"] == self.NOT_FOUND:
            raise self.ExtensionError("Extension not found")
        return event[0]["Status"]

