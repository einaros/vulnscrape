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
