class RefererSplittingInjection
  def run uri, *options
    test_uri = uri.clone
    hits = []
    header = String.random(5)
    value = String.random(5)
    magic = "#{String.random(5)}%0D%0A#{header}: #{value}"
    vuln = single_run(test_uri.to_s, magic, header, value)
    hits << test_uri.to_s if vuln
    hits
  end
  private
  def single_run url, magic, header, value
    page = Page.open(url, { 'Referer' => magic })
    return nil if page.nil? or page.response.body.nil?
    return page.response.header[header] == value
  end
end
