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
