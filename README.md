# Tiny Tripwire [![Compile](https://github.com/philcrump/tiny-tripwire/workflows/compile/badge.svg)](https://github.com/philcrump/tiny-tripwire/actions)

<p float="left">
  <img src="/logo-Lorc_Delapoite_contributors.png" width="25%" />
</p>

A minimal IDS. Uses libpcap to monitor an interface on specific ports, all events are logged and will trigger an email notification with a summary of all events after a configurable latency. Supports IPv4 & IPv6.

## Notable missing features

- [ ] Non-root user ability (or at self-demoting after libpcap setup)
- [ ] Support for the "any" Interface

## Dependencies

### Ubuntu 20.04+

```bash
sudo apt install build-essential libpcap-dev libcurl4-openssl-dev libjson-c-dev
```

### OUI MAC Address List

An OUI MAC Address list can be used to look up the manufacturer name listed against the MAC Address detected.

The latest list from the wireshark project can be downloaded to this directory with the following command:
```bash
curl -o manuf 'https://gitlab.com/wireshark/wireshark/-/raw/master/manuf'
```

The filename is configured in *config.json*. Failure to load the list is not a fatal error, setting the filename to "" will disable the lookup.

## Compilation

`make`

## Configuration

Copy and edit *config.json.template* file.

eg.
```json
{
	"listen": {
		"interface": "enp0s31f6",
		"icmp": true,
		"ports": [ 21, 22, 80, 443 ],
		"ignore_local_source": true
	},
	"notification": {
		"latency_seconds": 60,
		"email_destination": "phil@abc.co.uk",
		"email_source": "test@abc.co.uk",
		"email_subject": "Tiny-Tripwire Incident Report",
		"ouilist_filename": "manuf"
	},
	"smtp": {
		"hostname": "smtp.mailgun.org",
		"usessl": true,
		"usetls": false,
		"verifyca": false,
		"port": 465,
		"useauth": true,
		"username": "tripwire@abc.co.uk",
		"password": "not-a-real-password"
	}
}
```

## Run

```bash
./ttw -c <config filename>
```

### Install systemd service

```bash
sudo ./install
```

Service will now be running and enabled at boot, view log output with `sudo journalctl -f -u tinytripwire.service`

## Copyright

MIT licensed. © Phil Crump - phil@philcrump.co.uk

Derivations from other works are acknowledged in the source.

Logo © Lorc, Delapoite, & Contributors
