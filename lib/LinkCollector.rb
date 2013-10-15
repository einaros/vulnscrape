class LinkCollector
  attr_reader :uris
  attr_accessor :max_links, :ignored_extensions, :scraper_restriction, :url_restriction, :keep_duplicate_urls
  def initialize
    @uris = []
    @max_links = 0
    @ignored_extensions = %w{.png .jpg .jpeg .bmp .gif .tif .gz .tar .zip .rar .xap .swf .avi .wmv .mpg .pdf}
    @scraper_restriction = //
    @url_restriction = //
    @keep_duplicate_urls = false
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
      @uris = (@uris + links + css + images + scripts + script_links + forms + other + [baseuri]).uniq_by { |u| uri_fingerprint(u) }
    end
  end
  private
  def uri_fingerprint uri
    @keep_duplicate_urls ? uri.to_s.downcase : uri.normalized_site + uri.normalized_path
  end
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
      uri_fingerprint(u)
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
