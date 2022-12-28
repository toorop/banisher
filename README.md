# The Banisher

<p align="center">
  <img width="330" height="330" src="/etc/banisher.png">
</p>

The Banisher watches in real time your systemd journal and bans, via ipset and iptables, hosts who match on yours rules.  

Currently hosts (IP) are banished for 1 hour (configurable in config.yml).

The Banisher keeps states of banished IPs in a key-value store ([badger](https://github.com/dgraph-io/badger))   


## Getting started

__WARNING The Banisher works only with logs handled by systemd journal and is currently only available for Linux 64.__

### Installing

#### Without debian package

1. Download the lastest binary from the [releases section](https://github.com/olarriga/banisher/releases).
2. Set the exec flag (`chmod +x banisher`).
3. Create a [YAML](https://en.wikipedia.org/wiki/YAML) file named `config.yml` in the same directory than The Banisher binary to define the configuration.
4. Start The Banisher (`./banisher`).
 
#### With the debian package

1. Download the lastest debian package from the [releases section](https://github.com/olarriga/banisher/releases).
2. Modify the /etc/banisher.yml file to define the configuration according to your needs
3. Restart The Banisher (`systemctl restart banisher`).

### Config

Here is a sample: 

```yaml
# defaut banishment duration in seconds
defaultBanishmentDuration: 3600

# whitelisted IP
whitelist:
  - 178.22.51.92
  - 142.93.11.10

# rules
rules:
  - name: dovecot
    match: .*imap-login:.*auth failed,.*
    IPpos: 0

  - name: ssh
    match: Failed password.*ssh2
    IPpos: 0

```

Where:

- __defaultBanishmentDuration__: is the period in second, during which an IP will be banned, if it matches a rule.

- __whitelist__: a list of IPs that must not be banned

- __rules__ :your Banisher rules.

A rule has three poperties:
- __name__: is the name of the rule (whaoo amazing!)
- __match__: is a regular expression. If a log line matches this regex, The Banisher will ban IP address found in this line.
- __IPpos__: as some log line may have multiple IP, this property will indicate which IP to ban. __Warning__: index start at 0, so if you want to ban the first IP found (left to right) IPpos must be 0.

And... that it.

Here is some samples of rules:

##### SSH

A failed auth attempt, appears in log with this line:

```text
Failed password for invalid user mrpresidentmanu from XXX.XXX.XXX.XXX port 47092 ssh2
```

Here is the corresponding rule:

```yaml
- name: ssh
  match: Failed password.*ssh2
  IPpos: 0
```

##### Dovecot IMAP

Log line for [Dovecot](https://www.dovecot.org/) authentification failure looks like:

```text
imap-login: Disconnected (auth failed, 1 attempts in 3 secs): user=<tobe@rnotto.be>, method=PLAIN, rip=XXX.XXX.XXX.XXX, lip=YYY.YYY.YYY.YYY, TLS: Disconnected, session=<n48ImrmGRP6xth/K>
``` 

Here is the corresponding rule:

```yaml
- name: dovecot-imap
  match: .*imap-login:.*auth failed,.*
  IPpos: 0
```

Yes i know, it seems to too easy to be real.

#### Multiple rules ?

Of course you can have multiple rules in your config file, you just have to not forget the `-` prepending the `name` property for each rule.

For example if you want those two rules, your config file will be:

```yaml
- name: ssh
  match: Failed password.*ssh2
  IPpos: 0

- name: dovecot-imap
  match: .*imap-login:.*auth failed,.*
  IPpos: 0
```  

## And what can i do if something goes wrong ?

An iptables rules will be automaticaly removed after defaultBanishmentDuration (defined in your config file).

If you made a mistake, just:

- stop The Banisher
- remove badger files, the db.bdg folder.
- flush iptables INPUT chain `iptables -F INPUT`
- add your own iptables rules (if needed)   

## Build

### Prerequisite

- [Task](https://taskfile.dev/) is used for compilation with a Docker image to handle glibc version issue to keep The Banisher compatible with debian buster and bullseye (debian 10 and 11).
- To compile without the Docker image, the libsystemd0 library is needed (for debian like: `sudo apt install libsystemd-dev`).
- The Banisher is dynamically linked with the glibc.

### Build commands

- Compile The Banisher without Docker image : `task build`
- Generate the docker image to compile The Banisher : `task generate-docker-image`
- Compile The Banisher with Docker image : `task build-with-docker`
- Generate debian package : `task package`

The binaries will be in the "dist" folder.


