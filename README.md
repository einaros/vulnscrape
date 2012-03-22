## Author

Einar Otto Stangvik <einar@indev.no> <http://codefornuts.com>

## About

This is a rather naïve link scraper-driven web vulnerability scanner. Use it responsibly.

## Usage

    Usage: vulnscrape.rb [options]
        -u, --url URL                    The url to scan.
        -m, --max count                  Max urls to scrape for.
        -i, --skip count                 Numer of scraped urls to skip.
        -c, --scraper REGEX              Scraper restriction.
                                         Only scrape URLs matching REGEX.
        -r, --restriction REGEX          Url restriction
                                         Only collect URLs matching REGEX.
                                         Typically more restrictive than the scraper restriction.
        -k, --[no-]keep                  Keep duplicate urls.
                                         Enabling this will make the link collector keep urls with the same host and path.
                                         Default: false
        -h, --[no-]header                Include header heuristics. Default: false
        -p, --[no-]split                 Include response splitting heuristics. Default: false
        -n, --[no-]mhtml                 Include MHTML heuristics. Default: false
        -x, --[no-]hash                  Include hash heuristics. Default: false
        -q, --[no-]query                 Include query heuristics. Default: true
        -f, --[no-]fof                   Include 404 page. Default: true
        -s, --[no-]single                Single run. Default: false
            --user USERNAME              Basic auth username
            --pass PASSWORD              Basic auth password
            --cookie COOKIE              Cookie string
            --load FILENAME              Load urls from FILENAME
                                         The scraper can save urls using --save.
            --save FILENAME              Save urls to FILENAME
                                         Saved urls can be reloaded later with --load

## Examples

Straight forward scan:

    ./vulnscrape.rb -u http://mydomain.com -m 50

Will scrape http://mydomain.com for at least 50 urls, and start running various heuristics on it.

    ./vulnscrape.rb -u http://services.mydomain.com -m 50 -c "https?://services\.mydomain\.com" -r "https?://([^.]*?\.)*?mydomain.com"

Will start scraping at http://services.mydomain.com, and only follow (continue scraping) urls on that subdomain. All links from
all mydomain.com subdomains will eventually be run through the heuristics scanner.

    ./vulnscrape.rb -u http://xss.progphp.com -h -p -m -x

Includes header heuristics, as demonstrated by a few of the XSS vectors on the progphp test site.