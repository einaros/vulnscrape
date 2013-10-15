class Page
  attr_reader :response, :url, :header
  @@cookie = nil
  @@username = nil
  @@password = nil
  @@logger = nil
  def initialize response, url
    @response = response
    @url = url
    @header = response.header.to_hash.map { |k, v| "#{k}: #{v}" }.join('\r\n')
  end
  def self.set_cookie cookie
    @@cookie = cookie
  end
  def self.set_auth username, password
    @@username = username
    @@password = password
  end
  def self.set_logger logger
    @@logger = method
  end
  def self.open url, *headers
    redirect_history = []
    begin
      while true
        uri = Addressable::URI.parse(url)
        path = uri.path.empty? ? '/' : uri.path
        https = uri.scheme.downcase == 'https'
        port = uri.port.nil? ? (https ? 443 : 80) : uri.port
        http = Net::HTTP.new(uri.host, port)
        request = Net::HTTP::Get.new(uri.request_uri)
        request.basic_auth(@@username, @@password) if @@username and @@password
        header = headers[0]||{}
        header['User-Agent'] ||= 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4'
        header['Cookie'] = @@cookie if @@cookie
        request.initialize_http_header(header)
        http.use_ssl = https
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.start do |http|
          resp = http.request(request)
          case resp
          when Net::HTTPUnauthorized
            raise "Unauthorized request to #{uri}"
          when Net::HTTPRedirection
            url = resp['Location']
            if not url.start_with?('http')
              url = (uri + Addressable::URI.parse(url)).to_s
            end
          when Net::HTTPSuccess, Net::HTTPNotFound
            return self.new(resp, url)
          else
            raise "Unknown response #{resp.code}"
          end
        end
        raise 'Cyclic redirect' if redirect_history.include?(url)
        redirect_history << url
      end
    rescue
      log "Error: #{$!}"
    end
  end
  private
  def self.log *args
    @@logger.call(*args) if @@logger
  end
end