# dex

dex is an implementation of the Domain Name System (DNS). It includes an
authoritative nameserver and a command-line client (`dex`) that operates in a
manner similar to `dig`.

```shell
> dex unrealistic.dev NS
unrealistic.dev. IN 3600 NS dns2.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns3.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns4.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns1.p04.nsone.net.
```
