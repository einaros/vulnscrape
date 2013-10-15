#!/usr/bin/env ruby
#
# Author: Einar Otto Stangvik (einar@indev.no)
#         https://2x.io
#
# About: This is a rather naive link scraper-driven web vulnerability scanner. Use it responsibly.
#
# Todos:
#   - Add option which adds a callback and jsonp parameter in case the url ends with .json / .jsonp etc. => URL mutation.
#   - Something is off with the mime type / script injection check. Returns very bogus false positives for some domains.
#   - Write module to look for SQL injection vulnerabilities.

require 'open-uri'
require 'rubygems'
require 'nokogiri'
require 'net/http'
require 'net/https'
require 'uri'
require 'addressable/uri'
require 'optparse'
require './lib/util'
require './lib/Page'
require './lib/LinkCollector'
require './lib/Scanner'
Dir['./plugins/*.rb'].each { |e| require e }

class VulnScrape
  def initialize args
    @options = {
      :count => 100,
      :scraper_regexp => '',
      :url_regexp => '',
      :query => true,
      :hash => false,
      :header => false,
      :response_splitting => false,
      :mhtml => false,
      :fourohfour => true,
      :single => false,
      :skip => 0,
      :username => nil,
      :password => nil,
      :keep_duplicate_urls => false,
      :load => nil,
      :save => nil
    }
    OptionParser.new do |opts|
      opts.banner = "Usage: vulnscrape.rb [options]"
      opts.on("-u", "--url URL", "The url to scan.") do |url|
        @options[:url] = url
      end
      opts.on("-m", "--max count", Integer, "Max urls to scrape for.", "Default: #{@options[:count]}") do |count|
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
      opts.on("-k", "--[no-]keep", "Keep duplicate urls.",
                                   "Enabling this will make the link collector keep urls with the same host and path.",
                                   "Default: #{@options[:header]}") do |s|
        @options[:keep_duplicate_urls] = s
      end
      opts.on("-h", "--[no-]header", "Include header heuristics. Default: #{@options[:header]}") do |s|
        @options[:header] = s
      end
      opts.on("-p", "--[no-]split", "Include response splitting heuristics. Default: #{@options[:response_splitting]}") do |s|
        @options[:response_splitting] = s
      end
      opts.on("-n", "--[no-]mhtml", "Include MHTML heuristics. Default: #{@options[:mhtml]}") do |s|
        @options[:mhtml] = s
      end
      opts.on("-x", "--[no-]hash", "Include hash heuristics. Default: #{@options[:hash]}") do |s|
        @options[:hash] = s
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
      opts.on("--cookie COOKIE", "Cookie string") do |s|
        @options[:cookie] = s
      end
      opts.on("--load FILENAME", "Load urls from FILENAME",
                                 "The scraper can save urls using --save.") do |s|
        @options[:load] = s
      end
      opts.on("--save FILENAME", "Save urls to FILENAME",
                                 "Saved urls can be reloaded later with --load") do |s|
        @options[:save] = s
      end
    end.parse!(args)
    unless @options[:url] or @options[:load]
      raise "-u or --load required. try --help for guidance."
    end
  end
  def run
    @target = @options[:url]
    @collector = LinkCollector.new
    @collector.max_links = @options[:count]
    if @options[:single]
      scan_single_page
    else
      if @options[:load]
        uris = load_uris @options[:load]
      else
        uris = scrape
      end
      if @options[:save]
        save_uris(uris, @options[:save])
      end
      scan uris
    end
  end
  private
  def load_uris filename
    File.read(filename).split("\n").map { |line| Addressable::URI.parse(line) }
  end
  def save_uris uris, filename
    File.open(filename, 'w') do |file|
      uris.each do |uri|
        file.write "#{uri}\n"
      end
    end
  end
  def build_heuristic_collection
    heuristics = []
    heuristics << :query if @options[:query]
    heuristics << :mhtml if @options[:mhtml]
    heuristics << :header if @options[:header]
    heuristics << :hash if @options[:hash]
    heuristics << :response_splitting if @options[:response_splitting]
    heuristics
  end
  def scan_single_page
    heuristics = build_heuristic_collection
    Scanner::check_page(Addressable::URI.parse(@target), *heuristics)
  end
  def scrape
    Page.set_auth(@options[:username], @options[:password]) if @options[:username] and @options[:password]
    Page.set_cookie(@options[:cookie]) if @options[:cookie]
    @collector.scraper_restriction = Regexp.new(@options[:scraper_regexp], 'i')
    @collector.url_restriction = Regexp.new(@options[:url_regexp], 'i')
    @collector.keep_duplicate_urls = @options[:keep_duplicate_urls]
    show_crossdomain_policy
    @collector.collect("#{@target}/" + String.random(10)) if @options[:fourohfour]
    @collector.collect(@target, :deep_scrape, :collect_entire_domain)
    puts "Urls discovered: #{@collector.uris.map{|u|u.site+u.path}.inspect}\n\n"
    puts "#{@collector.uris.count} urls total"
    puts
    @collector.uris
  end
  def scan uris
    heuristics = build_heuristic_collection
    start_index = @options[:skip]
    uris[start_index..-1].each do |uri|
      Scanner::check_page(uri, *heuristics)
    end
  end
  def show_crossdomain_policy
    crossdom = Scanner::get_crossdomain_allows(@target)
    if crossdom and crossdom.count > 0
      puts "crossdomain.xml allows access from:"
      crossdom.each { |e| puts "  #{e}" }
      puts
    end
    crossdom = Scanner::get_clientaccespolicy_allows(@target)
    if crossdom and crossdom.count > 0
      puts "clientaccesspolicy.xml allows:"
      crossdom.each { |e| puts "  #{e}" }
      puts
    end
  end
end

begin
  VulnScrape.new(ARGV).run
rescue
  puts "Error: #{$!}"
end
