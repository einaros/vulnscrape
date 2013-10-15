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
        magic = "%3Cscript%3Ealert(#{String.random(5)})%3C/script%3E"
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
