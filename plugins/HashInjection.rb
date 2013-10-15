class HashInjection
  def run uri, *options
    test_uri = uri.clone
    magic = "<sc>al()</sc>"
    magic_test = /\<sc(\>|&gt;)al\(\)\<\/sc(\>|&gt;)/i
    page = Page.open("#{uri.to_s}##{magic}")
    return nil if page.nil? or page.response.body.nil?
    ["#{uri.to_s}##{magic}"] if (page.response.body =~ magic_test) != nil
  end
end