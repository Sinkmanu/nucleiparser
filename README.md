# Nuclei parser

A [Nuclei](https://github.com/projectdiscovery/nuclei) output parser for CLI

## Installation

```sh
pip install nucleiparser
```

### Manually installation

```
git clone https://github.com/sinkmanu/nucleiparser
cd nucleiparser
python3 setup.py install
```

## Usage

```
Usage: nparse [options]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  FILE with json output. If no FILE, uses stdin
  -c COLUMNS, --colums=COLUMNS
                        Columns to print (e.g. template-id,url,info.severity)
  -s SORT, --sort-by=SORT
                        Sort by arg (e.g. info.severity)
  -P, --pretty          Pretty print (default)
  -C, --csv             CSV print

  FILTER OPTIONS:
    --fs=FILTER, --filter-severity=FILTER
                        Filter level of severity (unknown, info, low, medium,
                        high, critical). Comma separated list for more than
                        one
    --ft=FILTER, --filter-template=FILTER
                        Filter by template-id. Comma separated list for more
                        than one
    --fu=FILTER, --filter-url=FILTER
                        Filter by url. Comma separated list for more than one
    --fh=FILTER, --filter-host=FILTER
                        Filter by host. Comma separated list for more than one
```

### Examples
```
cat example.com_nuclei.json |  nparse                               
+---------------------------------+---------------------------------------------+---------------+
|           template-id           |                     url                     | info.severity |
+---------------------------------+---------------------------------------------+---------------+
|          options-method         |        https://investor.example.com         |      info     |
|          generic-tokens         |        https://investor.example.com         |    unknown    |
|      aws-cloudfront-service     | https://api-weighted-production.example.com |      info     |
|      xss-deprecated-header      |        https://investor.example.com         |      info     |
|      aws-cloudfront-service     |           https://go.example.com            |      info     |
|      aws-cloudfront-service     |        https://clk.email.example.com        |      info     |
|      aws-cloudfront-service     |         https://eclick.example.com          |      info     |
|        aws-bucket-service       |          http://tools.example.com           |      info     |
|        aws-bucket-service       |           https://get.example.com           |      info     |
|      aws-cloudfront-service     |           https://get.example.com           |      info     |
|        aws-bucket-service       |           http://beta.example.com           |      info     |
|      aws-cloudfront-service     |         https://drivers.example.com         |      info     |
|        aws-bucket-service       |          https://take.example.com           |      info     |
|      aws-cloudfront-service     |          https://take.example.com           |      info     |
[REDACTED]
```

## Hacking

Pull requests are welcome. 

## License

[GPL](https://www.gnu.org/licenses/gpl-3.0.txt)
