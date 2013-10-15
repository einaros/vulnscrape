module Scanner
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
  def self.get_clientaccespolicy_allows url
    uri = Addressable::URI.parse(url)
    crossdomain = uri.scheme + "://" + uri.host + "/clientaccesspolicy.xml";
    page = Page.open(crossdomain)
    return nil unless page && page.response.code == "200"
    xml = Nokogiri::XML(page.response.body)
    xml.xpath("//cross-domain-access/policy").map do |n|
      domain = n.xpath("./allow-from/domain").attribute('uri')
      resources = n.xpath("./grant-to/resource")
      paths = resources.map { |e| e.attr('path') + (e.attr('include-subpaths') == 'true' ? ' (recursive)' : '') }.join(', ')
      "#{domain} can access: #{paths}"
    end
  end
  def self.check_page uri, *heuristics
    heuristics = heuristics.flatten
    qs_heuristics = heuristics.include?(:query) ? [ScriptInjection, ScriptLiteralInjection] : []
    qs_heuristics += [MHTMLInjection] if heuristics.include?(:mhtml)
    qs_heuristics += [ResponseSplittingInjection, RefererSplittingInjection] if heuristics.include?(:response_splitting)
    plain_heuristics = []
    plain_heuristics += [HeaderInjection] if heuristics.include?(:header)
    plain_heuristics += [HashInjection] if heuristics.include?(:hash)
    to_run = plain_heuristics + (uri.query ? qs_heuristics : [])
    heuristic_options = heuristics.select { |e| e.class == Hash }
    if not to_run.empty?
      puts "Checking: #{uri.site + uri.path}"
      puts "  : Query params: #{uri.query_values.keys.inspect}" if uri.query
      to_run.each do |type|
        to_run_options = heuristic_options.select { |k, v| k.to_s == type.to_s }.map { |k, v| v }
        hits = type.new.run(uri, to_run_options)
        result = hits.nil? || hits.empty? ? 'Nothing found' : "Possible vulnerability at\n\t" + hits.join("\n\t")
        puts "  [#{type}] #{result}"
      end
      puts
    end
  end
  def self.content_type? response, body_index
    return :js if response.content_type.downcase.include?('javascript')
    m = response.body[0..body_index].match(/.*<(\/?)script/im)
    return :js if m and m[1].empty?
    return :js if response.body[0..body_index].match(/.*'\s*javascript:([^']|\\')*\Z/im)
    return :js if response.body[0..body_index].match(/.*"\s*javascript:([^"]|\\")*\Z/im)
    :text
  end
end
