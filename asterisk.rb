#!/usr/bin/ruby -rubygems

require 'net/telnet'
begin
  require 'orderedhash'
rescue Exception; nil end

class Array
  def invoke(method, *args)
    self.map { |each| each.send method, *args }
  end

  def pluck(*args)
    self.invoke :[], *args
  end
end


class Hash
  def format
    self.map { |k, v| "#{k}: #{v}" }.join("\r\n") + "\r\n\r\n"
  end
end


class MatchData
  def to_hash(h=Hash)
    a = self.names.zip(self.captures).flatten
    h[*a]
  end
end


class AMI

  class ExecutionError < StandardError; end

  attr_reader :connection, :pump, :events
  attr_accessor :default_context

  def initialize(host, opts={})
    @listeners = {}
    @debugger = lambda { |x| STDERR.write "\n#{x.format}\n>>> " }
    @events = []
    begin
      @hash = OrderedHash
    rescue NameError
      @hash = Hash
    end

    @connection = Net::Telnet.new(
      "Host" => host, "Port" => opts[:port] || 5038,
      "Binmode" => true, "Telnetmode" => false
    )
    @connection.waitfor "Match" => /Asterisk Call Manager\/\d+\.\d+\r\n/

    @default_context = opts[:default_context] || "default"

    at_exit { self.logoff }
    @pump = Thread.new do
      while true
        r = /\r\n\r\n/
        resp = @connection.waitfor("Match" => r, "Timeout" => false).split(r).map { |x| self.parse x }
        @events.concat resp
        self.dispatch_events resp
        sleep 0.01 
      end
    end
  end

  def inspect
    fields = %w(@connection @pump @hash @listeners)
    fields.map! { |f| "#{f}=" + self.instance_variable_get(:"#{f}").inspect }
    "#<#{self.class} #{fields.join(", ")}>"
  end

  def parse(string)
    if string =~ /^Response: Follows/
      # Telnet#waitfor strips off the matching token
      string.sub!(/--END COMMAND--$/m, '')
      sep = string.rindex "\r\n"
      results = string[(sep + 2)..-1].strip
      keys = string[0...sep].rstrip
      resp = keys.split("\r\n").map { |n| n.split(": ") }.map do |n| 
        [n.first, n[1..-1].join(": ").strip]
      end.concat ["Results", results]
    else
      resp = string.split("\r\n").reject { |x| x.empty? }.map do |x|
        x = x.split(/: /)
        [x[0], x[1..-1].join(sep)]
      end
    end
    @hash[*resp.flatten!]
  end

  def cmd(cmd)
    @connection.write(cmd + "\r\n\r\n")
    cmd
  end

  def dispatch_events(events)
    events.each do |e|
      listeners = @listeners[e["Event"] || e["Response"]] || []
      listeners.concat(@listeners['*'] || [])
      listeners.each { |l| Thread.new { l.call(e) } }
    end
  end

  def attach(events, &f)
    events = [events] unless events.is_a? Array
    events.each do |e|
      @listeners[e] = [] if not @listeners[e]
      @listeners[e] << f
    end
  end

  def detach(event, &f)
    return nil if @listeners[event].nil?
    return @listeners.delete(event) if event and f.nil?
    @listeners[event].delete(f)
  end

  def debug=(v)
    (@debug = !!v) ? self.attach('*', &@debugger) : self.detach('*', &@debugger)
  end
  attr_reader :debug

  def do_action(action, opts={})
    opts["ActionID"] ||= "#{action.downcase}-#{Time.now.to_f}"
    vars = opts.map { |k, v| "#{k.to_s.capitalize}: #{v}" }.join("\r\n")
    vars = "\r\n" + vars if not vars.empty?
    self.cmd("Action: #{action.capitalize}#{vars}")
    opts["ActionID"]
  end

  def login(username, secret, opts={})
    self.do_action "Login", opts.merge(:username => username, :secret => secret)
  end
  def logoff; self.do_action "Logoff"; end
  def ping; self.do_action "Ping"; end

  def call(channel, exten, opts={})
    self.do_action "Originate", opts.merge(
      :channel => channel, :exten => exten, :context => @default_context,
      :priority => 1, :async => "yes", :timeout => 60 * 1000
    )
  end

  def dial(channel, keys, interval=0.5)
    keys.split('').each do |c|
      self.do_action "PlayDTMF", {:channel => channel, :digit => c}
      sleep interval
    end
  end

  def hangup(channel); self.do_action "Hangup", {:channel => channel}; end

  def transfer(channel, exten, opts)
    self.do_action "Redirect", opts.merge(
      :channel => channel, :exten => exten, :context => @default_context,
      :priority => 1
    )
  end

  def command(cmd); self.do_action "Command", {:command => cmd}; end

  def execute(cmd)
    data = nil
    listener = lambda { |e| data = e["Results"] }
    handler = lambda { |e| data = ExecutionError.new e["Message"] }
    self.command cmd
    self.attach("Follows", &listener)
    self.attach("Error", &handler)
    while data.nil?; sleep 0.01; end
    self.detach("Error", &handler)
    self.detach("Follows", &listener)
    raise data if data.is_a? Exception
    data
  end
  alias :exec :execute
end


module AMICLIProxy
  def self.hash
    begin
      return OrderedHash
    rescue NameError
      return Hash
    end
  end

  def execute(cmd); @connection.execute cmd; end
  alias :exec :execute

  def self.crunch_output(incoming, pattern, statistics=nil)
    stats = statistics.nil? ? nil : incoming.match(statistics)
    incoming.sub! statistics, '' unless statistics.nil?
    data = []
    incoming.each_line { |line| data << line.match(pattern) }
    {:data => data.compact.map { |match| match.to_hash self.hash }, :stats => stats}
  end
end


class Channel
  
  class ChannelError < StandardError
  end

  def initialize(connection, name, info=nil)
    @connection = connection
    @name = name
    @first_inspection = true
    self.update_info(info)
  end
  attr_reader :connection, :name
  alias :to_s :name

  def self.process_event(event)
    strip = %w(Event Privilege ActionID Uniqueid)
    e = event.dup; strip.each { |k| e.delete k }
    add = e.respond_to?(:unshift) ? :unshift : :store
    e.send add, "Name", e.delete("Channel")
    e
  end

  def self.fetch_info(connection, channel=nil)
    id = nil
    eos = false
    events = []
    action_keys = {}
    err_message = nil
    listener = lambda do |e|
      return if e["ActionID"] != id
      case e["Event"]
        when "StatusComplete" then
          eos = true
        when "Status" then
          events << self.process_event(e)
        else
          (err_message = e["Message"]; eos = true) if e["Response"] == "Error"
      end
    end
    action_keys[:channel] = channel if not channel.nil?
    id = connection.do_action "Status", action_keys
    connection.attach('*', &listener)
    while eos == false
      sleep 0.01
    end
    connection.detach('*', &listener)
    raise ChannelError.new err_message if not err_message.nil?
    channel.nil? ? events : events.first
  end

  def self.list(connection)
    self.fetch_info(connection).map { |x| Channel.new connection, x["Name"], x }
  end

  def inspect
    unless @first_inspection
      self.update_info
    else
      @first_inspection = false
    end
    fields = @inspectable_fields.empty? ? ["@name"] : @inspectable_fields.dup
    fields.map! { |f| "#{f}=" + self.instance_variable_get(:"#{f}").inspect }
    "#<#{self.class} #{fields.join(", ")}>"
  end

  def update_info(info=nil)
    info ||= self.class.fetch_info(@connection, @name)
    @inspectable_fields = []
    info.keys.each do |k|
      m = k.gsub(/([A-Z])([A-Z]*)([A-Z])/) do |s|
        "#{$1}#{$2.downcase}#{$3}"
      end.gsub(/([a-z])([A-Z])/) { |s| "#{$1}_#{$2}" }.downcase
      attr = :"@#{m}"
      self.class.send(:define_method, m) do
        self.update_info
        self.instance_variable_get attr 
      end unless self.respond_to? m
      info[k] = info[k].to_i(10) if %w(priority seconds).include? m
      self.instance_variable_set attr, info[k]
      @inspectable_fields << attr unless @inspectable_fields.include? attr
    end
  end
  
  def dial(*args) @connection.dial @name, *args end
  def hangup(*args) @connection.hangup @name, *args end
  def transfer(*args) @connection.transfer @name, *args end
end


class Conference
  include AMICLIProxy

  @@pattern = /
    (?<number>   \d+)            \s+
    (?<parties>  0*\d+)          \s+
    (?<marked>   .+?)            \s+
    (?<activity> \d\d:\d\d:\d\d) \s+
    (?<creation> .+?)            \s+
  /x
  @@statistics = /
    Conf\s Num\s+ Parties\s+ Marked\s+ Activity\s+ Creation\s* \n
    |\n
    \*\s Total\s number\s of\s MeetMe\s users:\s (?<users> \d+)
  /mx

  @@users = /
    User\s \#:\s (?<user>     \d+)            \s+
                 (?<exten>    \d+)            \s+
                 (?<name>     .+?)            \s+
      Channel:\s (?<channel>  .+?)            \s+
                 (?<status>   \(.+\))         \s+
                 (?<duration> \d\d:\d\d:\d\d) \s*
  /x
  @@users_statistics = /\n
    (?<number> \d+)\s users\s in\s that\s conference\.
  /mx

  def initialize(connection, number, info=nil)
    super()
    @connection = connection
    @number = number
    if not info.nil?
      info.delete "number"
      info["parties"] = info["parties"].to_i 10 if info["parties"]
    end
    self.update_info info
  end

  def inspect
    fields = %w(@number @parties @marked @activity @creation)
    fields.map! { |f| "#{f}=" + self.instance_variable_get(:"#{f}").inspect }
    "#<#{self.class} #{fields.join(", ")}>"
  end

  def self.fetch_info(connection)
    data = connection.exec("meetme")
    return [] if data == "No active MeetMe conferences."
    AMICLIProxy::crunch_output(data, @@pattern, @@statistics)[:data]
  end

  def self.list(connection)
    results = self.fetch_info connection
    results.map { |c| Conference.new connection, c["number"], c }
  end

  def update_info(info=nil)
    info ||= self.class.fetch_info(@connection).find do |x|
      x["number"] == @number.to_s
    end
    info.delete "parties"
    info.each do |k, v|
      self.instance_variable_set :"@#{k}", v 
      self.class.send(:define_method, k) do
        self.update_info
        self.instance_variable_get :"@#{k}"
      end if not self.respond_to? k
    end
  end

  def participants
    data = self.exec "meetme list #{@number}"
    return [] if data == "No active conferences." or data.nil?
    results = AMICLIProxy::crunch_output(data, @@users, @@users_statistics)[:data]
  end
  alias :users :participants
  alias :parties :participants

  def lock
    self.exec "meetme lock #{@number}"
  end

  def unlock
    self.exec "meetme unlock #{@number}"
  end

  def kick(user)
    self.exec "meetme kick #{@number} #{user}"
  end

  def kick_all; self.kick("all"); end

  def mute(user)
    self.exec "meetme mute #{@number} #{user}"
  end

  def unmute(user)
    self.exec "meetme unmute #{@number} #{user}"
  end
end


class Extension
  NOT_FOUND = -1
  IDLE = 0
  IN_USE = 1
  BUSY = 2
  UNAVAILABLE = 4
  RINGING = 8
  ON_HOLD = 16

  class ExtensionError < StandardError; end

  def initialize(connection, name, context=nil)
    @connection = connection
    @name = name
    @context = context || connection.default_context
  end

  def inspect
    fields = %w(@name @context)
    fields.map! { |f| "#{f}=" + self.instance_variable_get(:"#{f}").inspect }
    "#<#{self.class} #{fields.join(", ")}>"
  end

  def status
    id = nil
    eos = false
    event = nil
    action_keys = {:exten => @name}
    listener = lambda { |e| (event = e; eos = true) if e["ActionID"] == id }
    action_keys[:context] = @context if not @context.nil?
    id = @connection.do_action "ExtensionState", action_keys
    @connection.attach("Success", &listener)
    while eos == false
      sleep 0.01
    end
    @connection.detach("Success", &listener)
    event["Status"] = event["Status"].to_i
    raise ExtensionError.new "Extension not found" if event["Status"] == self.class::NOT_FOUND
    event["Status"]
  end
end

