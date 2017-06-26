## Description

Exploit Checker
- Find out what was the last vulnerability it found last time it was run
- Check the website for any new vulnerabilities since the last check
- Send an email to a particular email address with all the new vulnerabilities found. All the vulnerabilities should be sent in the same email
- Update it's storage of the last vulnerability found so that it doesn't email us again until a new vulnerability is published


## Requirements:

- Ruby


## Instructions
2) run `$ ./script.rb`


### Configuration
#### PRODUCTS
Array of products to search

`PRODUCTS = %w(openssl openvpn openssh ssl)`


#### STRICT_FILTER
Strict filter indicates search a whole word for product
`ssl` will match on `openssl` if strict filter is set to false.

`STRICT_FILTER  = false`


#### YEARS
Array of years to search for vulnerabilities.
Leave empty to fetch only the `recent` ones.

`YEARS = [2016, 2017]`


#### INCLUDE_RECENT
Include most recent(fresh) vulnerabilities.
Note: you can't disable it if you don't have at least one year on the `YEARS` option.

`INCLUDE_RECENT = true`


#### DATABASE
File to save the tmp database.

`DATABASE = 'openssl.lock'`


#### SEND_EMAIL
Enable/Disable email. database will NOT be saved if email is DISABLED!

`SEND_EMAIL = true`


#### EMAIL
Array with all the configurations (except password) for email

```
    SMTP = {
      :from    => 'from@hotmail.com',
      :to      => 'to@domain.com',
      :host    => 'smtp.live.com',
      :port    => 25,
      :ssl     => true
    }
```

#### PASSWORD:
Fill your details on the `env.sh.sample`, rename it to `.env.sh` and source it `source .env.sh` this prevent credentials leaking.
