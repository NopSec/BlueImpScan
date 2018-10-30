# PoC for CVE-2018-9206

## About

Based on the following:

[original Poc](https://github.com/lcashdol/Exploits/tree/master/CVE-2018-9206)

[Python Poc](https://github.com/Den1al/CVE-2018-9206)

## Usage

```
usage: BlueimpScan.py [-h] [-p PREFIX] [-u USER_AGENT] host

CVE-2018-9206 PoC, initial release by Den1al, enhanced by NopSec

positional arguments:
  host                  the host to check, host:port, or CIDR range

optional arguments:
  -h, --help            show this help message and exit
  -p PREFIX, --prefix PREFIX
                        The prefix for the path
  -u USER_AGENT, --user-agent USER_AGENT
                        The user agent to send the requests with
```

## Dependencies

```
pip3 install -r requirements.txt
```

## Useful stuff to know

* The path prefix is set to "jQuery-File-Upload-9.22.0", this may not reflect the default path of the vulnerable files on your server(s).  If the default setting fails I'd recommend trying "jQuery-File-Upload".

* There is no output for hosts that are not vulnerable.  

## Authors
[Larry Cashdollar](https://twitter.com/_larry0)

[Daniel Abeles](https://twitter.com/Daniel_Abeles)

[Shawn Evans](https://github.com/shawndevans)
