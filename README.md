## Author

Einar Otto Stangvik <einar@indev.no> <http://codefornuts.com>

## About

This is a rather naïve link scraper-driven web vulnerability scanner. Use it responsibly.

## Examples

Straight forward scan:

    ./vulnscrape.rb -u http://mydomain.com -m 50

Will scrape http://mydomain.com for at least 50 urls, and start running various heuristics on it.

    ./vulnscrape.rb -u http://services.mydomain.com -m 50 -c "https?://services\.mydomain\.com" -r "https?://([^.]*?\.)*?mydomain.com"

Will start scraping at http://services.mydomain.com, and only follow (continue scraping) urls on that subdomain. All links from
all mydomain.com subdomains will eventually be run through the heuristics scanner.
