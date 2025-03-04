## What does it do?
This is a very simple script that just matches gateway down and gateway up alerts in Sophos central and matches them before resolving them. Right now it is only looking at Gateways, but that can easily be added on to.

## How do I use this?
I designed it to be deployed with Azure functions, but a cron job on any linux server would do the same thing with just a couple small modifications to the code.

## How was this tested?
I did a little testing on my own Central account. It didn't error and correctly resolved all alerts during testing without missing anything or incorrectly matching things, but I make no guarantees on reliability.

### Future Goals:
- Ping Gateway of firewall to verify that it is actually online (This may require a key value pair for each firewall gateway and the IP)
- Check status and resolve alerts for firewalls disconnecting from Central
- Switch to http for triggering the script to run (It would make it easier for an automated system to trigger it on an event)
- Use Azure Key Vault for storing client secret, id, and tenet id.