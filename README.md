﷽

# Residue PHP Client
A very simple, secure PHP library to interact with residue seamlessly.

This library provides interface for connecting and interacting with residue server seamlessly, means, once you are connected this module takes care of expired tokens and clients and keep itself updated with latest tokens and ping server when needed to stay alive.

[![Version](https://img.shields.io/github/release/muflihun/residue-php.svg)](https://github.com/muflihun/residue-php/releases/latest) [![GitHub license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/muflihun/residue-php/blob/master/LICENCE) [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

[**This is in early stages of development and should not be used in production**]

## Dependencies
This library currently depends on following binaries

 * `ripe`
 * `nc` (netcat)

Please check out [sample configuration](/samples/client.conf.json) to find out more

## Progress
Does not support following features at the moment

 * Unknown clients
 * Bulk requests
 * Compression (will require when bulk requests is done)
 * UTC time with log message
 * Time offset with log message
 * Custom key size
 * Reset connection when server restarted or reset

## Config

| **Config** | **Type** | **Description** |
|------------|----------|-----------------|
| `url`      | String   | Combination of URI and port of residue server |
| `access_codes`      | Object   | Array of access codes |
| `application_id`      | String   | Application ID for `%app` format specifier |
| `rsa_key_size`      | Number   | RSA key size (generated randomly) for unknown clients |
| `utc_time`      | Boolean   | Use UTC time instead of local time (Optional) |
| `client_id`      | String   | Client ID that server knows this client as |
| `client_private_key`      | String   | Full path of RSA private key |
| `client_key_secret`      | String   | Secret (passphrase) for encrypted private key (if any) |
| `server_public_key`      | String   | Full path to server public key (if any) |
| `ripe_bin`      | String   | Command to successfully run [ripe](https://github.com/muflihun/ripe) binary using user that will run your PHP script |
| `nc_bin`      | String   | Command to successfully run [nc](https://linux.die.net/man/1/nc) binary using user that will run your PHP script |
| `session_dir`      | String   | Full path to empty directory for storing temporary objects by script (e.g, connection params, tokens etc) |
| `reset_conn`      | Number   | Resets the connection and ignores objects in `session_dir` after these seconds |

### Sample Config
```
{
    "url": "residue-server:8777",
    "access_codes": [
        {
            "logger_id": "sample-app",
            "code": "a2dcb"
        }
    ],
    "application_id": "com.muflihun.residue.sampleapp",
    "rsa_key_size": 2048,
    "utc_time": false,
    "time_offset": 0,
    "client_id": "muflihun00102030",
    "client_private_key": "keys/muflihun00102030.pem",
    "client_key_secret": "",
    "server_public_key": "keys/server.pub.pem",
    "ripe_bin": "ripe",
    "nc_bin": "nc",
    "session_dir": "/tmp/resphp/",
    "reset_conn": 120
}
```
