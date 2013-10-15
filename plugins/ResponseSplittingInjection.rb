class ResponseSplittingInjection
  def run uri, *options
    test_uri = uri.clone
    hits = []
    test_uri.query_values.each do |key, value|
      qv = uri.query_values.clone
      header = String.random(5)
      value = String.random(5)
      magic = "#{String.random(5)}\r\n#{header}: #{value}"
      qv[key] = magic
      test_uri.query_values = qv
      vuln = single_run(test_uri.to_s, magic, header, value)
      hits << test_uri.to_s if vuln
    end
    hits
  end
  private
  def single_run url, magic, header, value
    page = Page.open(url)
    return nil if page.nil? or page.response.body.nil?
    return page.response.header[header] == value
  end
end
