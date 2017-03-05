# sslexpired: an HTTP(S) service to check if an SSL certificate will expire soon
[![Build Status](https://travis-ci.org/shaftoe/sslexpired.svg?branch=master)](https://travis-ci.org/shaftoe/sslexpired)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/shaftoe/sslexpired)](https://goreportcard.com/report/github.com/shaftoe/sslexpired)
[![Issue Count](https://codeclimate.com/github/shaftoe/sslexpired/badges/issue_count.svg)](https://codeclimate.com/github/shaftoe/sslexpired)

[_sslexpired_][5] is a small [serverless][4] project written in [Go][1] for the [OpenWhisk][2] platform to quickly verify if an SSL certificate hosted at `https://<your_domain_here>` is going to expire any soon.

## Usage

By default, response will contain an `alert:true` key if the certificate is expiring in less then 30 days (or if the host is not mentioned between the valid ones):

    $ curl https://sslexpired.info/google.com
    {
      "notAfter": "2017-05-17 08:58:00 +0000 UTC",
      "daysTolerance": 30,
      "host": "google.com",
      "response": "SSL certificate for google.com will expire in 72 days",
      "validHosts": ["*.android.com", [...cut...],
      "daysLeft": 72
    }

The `days` parameter can be used to tweak the check tolerance, for example this request will alert because the certificate is expiring in 72 days and we ask for at least 100 days of validity:

    $ curl https://sslexpired.info/google.com?days=100
    {
      "notAfter": "2017-05-17 08:58:00 +0000 UTC",
      "daysTolerance": 100,
      "alert": true,
      "host": "google.com",
      "response": "SSL certificate for google.com will expire in 72 days",
      "validHosts": ["*.android.com", [...cut...],
      "daysLeft": 72
    }

## Current limitations

- checks for expiration timestamp only, doesn't actual verify SSL validity
- only DNS names supported (i.e. no IP addresses)

## Develop on OpenWhisk

Fetch the development environment installing [OpenWhisk development Vagrant box][3] and set up credentials for `wsk` tool as suggested

### Deploy sslexpired action and api gateway

    $ ./build.sh create
    # ... edit code ...
    $ ./build.sh update

### Invoke sslexpired action

    $ ./build.sh run <project_name>

or fetch the api URL and use an http client

    $ wsk -i api-experimental list /sslexpired
    $ curl <https url>/?project=<project_name>

### Destroy sslexpired

    $ ./build.sh delete

[1]: https://golang.org/ "Go"
[2]: http://openwhisk.org/ "OpenWhisk"
[3]: https://github.com/openwhisk/openwhisk#quick-start "OpenWhisk devel quick start"
[4]: https://en.wikipedia.org/wiki/Serverless_computing
[5]: https://sslexpired.info/
