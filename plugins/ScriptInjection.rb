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
