# Dex

Dex is an implementation of the Domain Name System (DNS). It includes an
authoritative nameserver and a command-line client (`dex`) that operates in a
manner similar to `dig`.

```shell
> dex unrealistic.dev NS
unrealistic.dev. IN 3600 NS dns2.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns3.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns4.p04.nsone.net.
unrealistic.dev. IN 3600 NS dns1.p04.nsone.net.
```

## Installation

To install the CLI from source, you will need the Rust toolchain. Clone this
package, and then run the following command from the root directory of the
package: `cargo install --path .` This will build and install the CLI to your
environment.
