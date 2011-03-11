#!/usr/bin/env ruby
#
# Author: Einar Otto Stangvik (einar@indev.no)
#         http://codefornuts.com
#
# About: This is a rather naïve link scraper-driven web vulnerability scanner. Use it responsibly.
#
# Todos:
#   - Add option which adds a callback and jsonp parameter in case the url ends with .json / .jsonp etc. => URL mutation.
#   - Something is off with the mime type / script injection check. Returns very bogus false positives for some domains.
#   - Should also do something with the escaping injection, since it's only valid if we're able to inject a lone backslash + escaped quote.
#   - Track hash injections?

require 'open-uri'
require 'rubygems'
require 'nokogiri'
require 'net/http'
require 'net/https'
require 'uri'
require 'addressable/uri'
require 'optparse'
 
class Array
  def uniq_by
    h = {}; 
    inject([]) {|a,x| h[yield(x)] ||= a << x}
  end
end

class String
  def self.random length
    (0...length).map{ ('a'..'z').to_a[rand(26)] }.join
  end
  def each_match regex, &block
    md = regex.match(self)
    offset = 0
    while md
      block.call(md, offset + md.offset(0)[0])
      offset += md.offset(0)[1]
      md = regex.match(md.post_match)
    end
  end
  def map_match regex, &block
    md = regex.match(self)
    offset = 0
    a = []
    while md
      a << block.call(md, offset + md.offset(0)[0])
      offset += md.offset(0)[1]
      md = regex.match(md.post_match)
    end
    a
  end
end

class Page
  attr_reader :response, :url, :header
  @@username = nil
  @@password = nil
  @@logger = nil
  def initialize response, url
    @response = response    
    @url = url
    @header = response.header.to_hash.map { |k, v| "#{k}: #{v}" }.join('\r\n')
  end
  def self.set_auth username, password
    @@username = username
    @@password = password
  end
  def self.set_logger logger
    @@logger = method
  end
  def self.open url, *headers
    redirect_history = []
    begin
      while true
        uri = Addressable::URI.parse(url)
        path = uri.path.empty? ? '/' : uri.path
        https = uri.scheme.downcase == 'https'
        port = uri.port.nil? ? (https ? 443 : 80) : uri.port
        http = Net::HTTP.new(uri.host, port)
        request = Net::HTTP::Get.new(uri.request_uri)
        request.basic_auth(@@username, @@password) if @@username and @@password
        header = headers[0]||{}
        header['User-Agent'] ||= 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4'
        request.initialize_http_header(header)
        http.use_ssl = https
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.start do |http|
          resp = http.request(request)
          case resp
          when Net::HTTPUnauthorized
            raise "Unauthorized request to #{uri}"
          when Net::HTTPRedirection
            url = resp['Location']
            if not url.start_with?('http')
              url = (uri + Addressable::URI.parse(url)).to_s
            end
          when Net::HTTPSuccess, Net::HTTPNotFound
            return self.new(resp, url)
          else
            raise "Unknown response #{resp.code}"
          end
        end
        raise 'Cyclic redirect' if redirect_history.include?(url)
        redirect_history << url
      end
    rescue
      log "Error: #{$!}"
    end
  end
  private
  def self.log *args
    @@logger.call(*args) if @@logger
  end
end

class LinkCollector
  attr_reader :uris
  attr_accessor :max_links, :ignored_extensions, :scraper_restriction, :url_restriction
  def initialize
    @uris = []
    @max_links = 1000
    @ignored_extensions = %w{.png .jpg .jpeg .bmp .gif .zip .xap .rar .swf .avi .wmv .mpg .tif .tar .pdf}
    @scraper_restriction = //
    @url_restriction = //
  end
  def collect url, *options
    options = options.flatten
    start_uri = Addressable::URI.parse(url)
    return if @uris.find { |u| same_url?(start_uri, u) }
    iterator = @uris.length
    @uris << start_uri
    while iterator < @uris.length and @uris.length < @max_links
      uri = @uris[iterator]
      iterator += 1
      next unless uri == start_uri or @scraper_restriction.match(uri.site + uri.path)
      puts "Scraping #{uri.to_s} - #{@uris.length} found thus far"
      page = Page.open(uri.to_s)
      if page.nil?
        @uris.delete(uri)
        next
      end
      url = page.url
      puts "Redirected to #{url}" if uri.to_s != url
      filter_options = options.select { |o| [:collect_entire_domain].include?(o) }
      baseuri = Addressable::URI.parse(url)
      doc = Nokogiri::HTML(page.response.body)
      links = filter_urls(baseuri, doc.xpath('//a[@href]').map { |a| a.attribute('href').value }, filter_options)
      css = filter_urls(baseuri, doc.xpath('//link[@href]').map { |a| a.attribute('href').value }, filter_options)
      images = filter_urls(baseuri, doc.xpath('//img[@src]').map { |a| a.attribute('src').value }.select { |l| l.include?('?') }, filter_options)
      scripts = filter_urls(baseuri, doc.xpath('//script[@src]').map { |a| a.attribute('src').value }, filter_options)
      script_links = filter_urls(baseuri, scripts.map { |s| scrape_script(s.to_s) }.flatten, filter_options)
      forms = filter_urls(baseuri, collect_forms(doc), filter_options)
      other = options.include?(:deep_scrape) ? filter_urls(baseuri, scrape_body(page.response.body), filter_options) : []
      @uris = (@uris + links + css + images + scripts + script_links + forms + other + [baseuri]).uniq_by { |u| u.normalized_site + u.normalized_path }
    end
  end
  private
  def same_url? uri1, uri2
    (uri1.normalized_site + uri1.normalized_path) == (uri2.normalized_site + uri2.normalized_path)
  end
  def filter_urls baseuri, links, *options
    options = options.flatten
    links.map do |l|
      next nil if l.match(/\A(javascript:|mailto:)/i)
      begin
        uri = Addressable::URI.parse(l)
      rescue
        next nil
      end
      uri = baseuri + uri if uri.site.nil?
      next nil if uri.scheme.nil? and uri.site.gsub(/\//, '').empty?
      uri.scheme = 'http' if uri.scheme.nil?
      next nil if @ignored_extensions.include?(uri.extname.downcase)
      uri
    end.select do |u|
      u != nil and 
      u.normalized_scheme.match(/https?/) and 
      u.host != nil and
      same_domain?(u.normalized_host, baseuri.normalized_host, options.include?(:collect_entire_domain)) and
      @url_restriction.match(u.to_s)
    end.uniq_by do |u| 
      u.normalized_site + u.normalized_path
    end
  end
  def same_domain? hostA, hostB, entire_domain
    (entire_domain ? (domain_from_host(hostA) == domain_from_host(hostB)) : hostA == hostB)
  end
  def domain_from_host host
    host.gsub(/(.*\.)?([^\.]*\.[^\.]*)\Z/, '\2')
  end
  def collect_forms doc
    doc.xpath('//form[@method]').select do |a| 
      next false if a.attribute('action').nil?
      a.attribute('method').value.casecmp('get') == 0
    end.map do |a| 
      url = a.attribute('action').value
      uri = Addressable::URI.parse(url)
      a.xpath('.//input[@name]').each do |i| 
        uri.query = (uri.query.nil? ? '' : uri.query + '&') + i.attribute('name').value + '='
      end
      uri.to_s
    end
  end
  def scrape_script url
    page = Page.open(url)
    return [] if page.nil?
    regex = /('|")((https?:\/\/|\/)[^<>\[\]\r\n]*?)\1/
    md = regex.match(page.response.body)
    urls = []
    while md
      url = md.to_s[1..-2]
      # ignore slash only urls
      if not url.gsub(/\//, '').empty?
        # verify that the url is parsable
        uri = Addressable::URI.parse(url) rescue nil
        urls << url if uri
      end
      body = md.post_match
      md = regex.match(body)
    end
    urls
  end
  def scrape_body body
    regex = /('|")?((https?:\/\/|\/\/)[^<>\[\]\s\n\r]+?)(\1|\n|\r|<|>|\[|\]|\s)/
    md = regex.match(body)
    urls = []
    while md
      url = md.captures[1]
      # verify that the url is parsable
      uri = Addressable::URI.parse(url) rescue nil
      urls << url if uri
      body = md.post_match
      md = regex.match(body)
    end
    urls
  end
end

module Scanner
  def self.content_type? response, body_index
    return :js if response.content_type.downcase.include?('javascript')
    m = response.body[0..body_index].match(/.*<(\/?)script/im)
    return :js if m and m[1].empty?
    return :js if response.body[0..body_index].match(/.*'\s*javascript:([^']|\\')*\Z/im)
    return :js if response.body[0..body_index].match(/.*"\s*javascript:([^"]|\\")*\Z/im)
    :text
  end
  
  class MHTMLInjection
    def run uri, *options
      test_uri = uri.clone
      hits = []
      test_uri.query_values.each do |key, value|
        qv = uri.query_values.clone
        magic = "#{String.random(5)}\r\n#{String.random(5)}"
        qv[key] = magic
        test_uri.query_values = qv
        vuln = single_run(test_uri.to_s, magic)
        hits << test_uri.to_s if vuln
      end
      hits
    end
    private
    def single_run url, magic
      page = Page.open(url)
      return nil if page.nil? or page.response.body.nil?
      index = (page.response.body =~ /(\A|\r?\n)\r?\n/)||page.response.body.length
      return page.response.code == '200' && (page.response.body[0, index] =~ Regexp.new(magic)) != nil
    end
  end

  class ScriptInjection
    def run uri, *options
      test_uri = uri.clone
      magic = "<sc>al()</sc>"
      magic_test = /\<sc(\>|&gt;)al\(\)\<\/sc(\>|&gt;)/i
      hits = []
      test_uri.query_values.each do |key, value|
        qv = uri.query_values.clone
        qv[key] = magic
        test_uri.query_values = qv
        vuln = single_run(test_uri.to_s, magic_test)
        hits << "#{vuln} at #{test_uri.to_s}" if vuln
      end
      hits
    end
    private
    def single_run url, test
      page = Page.open(url)
      return nil if page.nil? or page.response.body.nil?
      return 'body' if (page.response.body =~ test) != nil
      return 'header' if (page.header =~ test) != nil
    end
  end

  class ScriptLiteralInjection
    def run uri, *options
      test_uri = uri.clone
      hits = []
      test_uri.query_values.each do |key, value|
        qv = uri.query_values.clone        
        vuln = single_run(test_uri, qv, key)
        hits << "#{test_uri.to_s}" if vuln
      end
      hits
    end
    private
    def single_run uri, qv, key
      [:injected_into_literal?].all? { |f| send(f, uri, qv, key) } and
      [:has_backslash?, :has_quote?].any? { |f| send(f, uri, qv, key) }
    end
    def injected_into_literal? uri, qv, key
      magic = String.random(10)
      qv[key] = magic
      uri.query_values = qv
      page = Page.open(uri.to_s)
      return false if page.nil? or page.response.body.nil?
      match = page.response.body.match(Regexp.new("('[^\\n']*#{magic}[^']*'|\"[^\\n\"]*#{magic}[^\"]*\")"))
      match != nil
    end
    def has_backslash? uri, qv, key
      magic = String.random(10) + '\\' + 'b'
      qv[key] = magic
      uri.query_values = qv
      page = Page.open(uri.to_s)
      return false if page.nil? or page.response.body.nil?
      page.response.body.map_match(Regexp.new("('[^\\n']*#{magic}\\\\[^'\\\\]*'|\"[^\\n\"]*#{magic}\\\\[^\"\\\\]*\")")) do |m, o| 
        Scanner.content_type?(page.response, o)
      end.any? { |e| e == :js }
    end
    def has_quote? uri, qv, key
      ['\'\'', '""'].any? do |e|
        magic = String.random(10) + e
        qv[key] = magic
        uri.query_values = qv
        page = Page.open(uri.to_s)      
        return false if page.nil?
        page.response.body.map_match(Regexp.new("[^\\n#{e}]*#{magic}[^#{e}]*#{e}")) do |m, o| 
          Scanner.content_type?(page.response, o)
        end.any? { |e| e == :js }
      end
    end
  end

  class HeaderInjection
      def run uri, *options
      headers = ['Accept', 'Accept-Encoding', 'Accept-Language', {'Cookie' => lambda { |v| "foo=#{v}" }}, 'Referer', 'Content-Type', 'User-Agent']
      injection_headers = InjectionHeader.generate_from(headers)
      page = Page.open(uri.to_s, injection_headers.map { |i| i.get_header }.reduce(:merge))
      vuln_headers = []
      if page
        regex = Regexp.new('\<script\>alert\([a-z]{5}\)\<\/script\>')
        match = regex.match(page.response.body)
        while match
          successful_injection = injection_headers.find { |v| v.value == match.to_s }
          vuln_headers << successful_injection.name if successful_injection
          match = regex.match(match.post_match)
        end
      end
      vuln_headers
    end
    private
    class InjectionHeader
      attr_reader :name, :value
      def initialize name, value, formatter
        @name = name
        @value = value
        @formatter = formatter||lambda{|v|v}
      end
      def get_header
        {@name => @formatter.call(@value)}
      end
      def self.generate_from headers
        headers.map do |h|
          magic = "<script>alert(#{String.random(5)})</script>"
          if h.is_a?(String)
            next InjectionHeader.new(h, magic, nil)
          elsif h.is_a?(Hash)
            h = h.first
            next InjectionHeader.new(h[0], magic, h[1])
          end
        end
      end
    end
  end
  
  def self.get_crossdomain_allows url
    uri = Addressable::URI.parse(url)
    crossdomain = uri.scheme + "://" + uri.host + "/crossdomain.xml";
    page = Page.open(crossdomain)
    return nil unless page && page.response.code == "200"
    xml = Nokogiri::XML(page.response.body)
    xml.xpath("//allow-access-from").map do |n| 
      secure = ((v=n.attribute('secure')) && v.value.match(/true/)) || (v == nil && page.url.match(/\Ahttps/i))
      "#{n.attribute('domain').value} #{secure ? 'secure' : ''}"  
    end
  end
  
  def self.check_page uri, *options
    options = options.flatten
    qs_heuristics = options.include?(:qs_heuristics) ? [MHTMLInjection, ScriptInjection, ScriptLiteralInjection] : []
    header_heuristics = options.include?(:header_heuristics) ? [HeaderInjection] : []
    to_run = (header_heuristics + (uri.query ? qs_heuristics : []))
    heuristic_options = options.select { |e| e.class == Hash }
    if not to_run.empty?
      puts "Checking: #{uri.site + uri.path}"
      puts "  : Query params: #{uri.query_values.keys.inspect}" if uri.query
      to_run.each do |type|
        to_run_options = heuristic_options.select { |k, v| k.to_s == type.to_s }.map { |k, v| v }
        hits = type.new.run(uri, to_run_options)
        result = hits.empty? ? 'Nothing found' : "Possible vulnerability at\n\t" + hits.join("\n\t")
        puts "  [#{type}] #{result}"
      end    
      puts
    end
  end
end

class VulnScrape
  def initialize args
    @options = {
      :count => 10,
      :scraper_regexp => '',
      :url_regexp => '',
      :query => true,
      :header => false,
      :fourohfour => true,
      :single => false,
      :skip => 0,
      :username => nil,
      :password => nil
    }
    OptionParser.new do |opts|
      opts.banner = "Usage: vulnscrape.rb [options]"
      opts.on("-u", "--url URL", "The url to scan.") do |url|
        @options[:url] = url
      end
      opts.on("-m", "--max count", Integer, "Max urls to scrape for.") do |count|
        @options[:count] = count
      end
      opts.on("-i", "--skip count", Integer, "Numer of scraped urls to skip.") do |count|
        @options[:skip] = count
      end
      opts.on("-c", "--scraper REGEX", "Scraper restriction.",
                                       "Only scrape URLs matching REGEX.") do |regexp|
        @options[:scraper_regexp] = regexp
      end
      opts.on("-r", "--restriction REGEX", "Url restriction",
                                           "Only collect URLs matching REGEX.",
                                           "Typically more restrictive than the scraper restriction.") do |regexp|
        @options[:url_regexp] = regexp
      end
      opts.on("-h", "--[no-]header", "Include header heuristics. Default: #{@options[:header]}") do |s|
        @options[:header] = s
      end
      opts.on("-q", "--[no-]query", "Include query heuristics. Default: #{@options[:query]}") do |s|
        @options[:query] = s
      end
      opts.on("-f", "--[no-]fof", "Include 404 page. Default: #{@options[:fourohfour]}") do |s|
        @options[:fourohfour] = s
      end
      opts.on("-s", "--[no-]single", "Single run. Default: #{@options[:single]}") do |s|
        @options[:single] = s
      end
      opts.on("--user USERNAME", "Basic auth username") do |s|
        @options[:username] = s
      end
      opts.on("--pass PASSWORD", "Basic auth password") do |s|
        @options[:password] = s
      end
    end.parse!(args)
    unless @options[:url]
      raise "-u argument required. try --help for guidance."
    end
  end
  def run
    @target = @options[:url]
    @collector = LinkCollector.new
    @collector.max_links = @options[:count]
    if @options[:single]
      scan_single_page
    else
      scrape_and_scan
    end
  end
  private
  def scan_single_page
    heuristics = []
    heuristics << :qs_heuristics if @options[:query]
    heuristics << :header_heuristics if @options[:header]
    Scanner::check_page(Addressable::URI.parse(@target), *heuristics)
  end
  def scrape_and_scan
    Page.set_auth(@options[:username], @options[:password]) if @options[:username] and @options[:password]
    @collector.scraper_restriction = Regexp.new(@options[:scraper_regexp], 'i')
    @collector.url_restriction = Regexp.new(@options[:url_regexp], 'i')
    show_crossdomain_policy
    @collector.collect("#{@target}/" + String.random(10)) if @options[:fourohfour]
    @collector.collect(@target, :deep_scrape, :collect_entire_domain)
    puts "Urls discovered: #{@collector.uris.map{|u|u.site+u.path}.inspect}\n\n"
    puts "#{@collector.uris.count} urls total"
    puts
    heuristics = []
    heuristics << :qs_heuristics if @options[:query]
    heuristics << :header_heuristics if @options[:header]
    start_index = @options[:skip]
    @collector.uris[start_index..-1].each do |uri|
      Scanner::check_page(uri, *heuristics)
    end
  end
  def show_crossdomain_policy
    crossdom = Scanner::get_crossdomain_allows(@target)
    if crossdom and crossdom.count > 0
      puts "crossdomain.xml allows swf posts from:"
      crossdom.each { |e| puts "  #{e}" }
      puts
    end
  end
end

begin
  VulnScrape.new(ARGV).run
rescue
  puts $!.to_s
end