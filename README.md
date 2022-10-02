# Tiny Tripwire [![Compile](https://github.com/philcrump/tiny-tripwire/workflows/compile/badge.svg)](https://github.com/philcrump/tiny-tripwire/actions)

<p float="left">
  <img src="/logo-Lorc_Delapoite_contributors.png" width="25%" />
</p>

A minimal IDS. Uses libpcap to monitor an interface on specific ports, all events are logged and will trigger an email notification with a summary of all events after a configurable latency.

## Dependencies

### Ubuntu 20.04+

```bash
sudo apt install build-essential libpcap-dev libcurl4-openssl-dev libjson-c-dev
```

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
		"ports": [ 21, 22, 80, 443 ]
	},
	"notification": {
		"latency_seconds": 60,
		"email_destination": "phil@abc.co.uk",
		"email_source": "test@abc.co.uk",
		"email_subject": "Tiny-Tripwire Incident Report"
	},
	"smtp": {
		"hostname": "smtp.mailgun.org",
		"usetls": false,
		"verifyca": false,
		"port": 465,
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
