# PvD and network namespace aware NetworkManager

**WARNING: This is a very alpha quality code! Use on your own risk!**

This is a fork of [NetworkManager](http://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/)
with added support for provisioning domains as defined by [IETF MIF working group](https://datatracker.ietf.org/wg/mif/charter/).
The plan is also to add support for network namespaces in NetworkManager.

In order to test this code you'll need:

1. Patched version of [libndp](https://github.com/jpirko/libndp) library with support for
   parsing PvDs in RA messages. You can find it [here](https://github.com/sgros/MIF_libndp).

2. Modified radvd deamon that sends PvD data. You can find it [here](https://github.com/dskvorc/mif-radvd).

3. This version of NetworkManager.

## TODO

The following items are on a todo list (in a random order):

1. Add basic network namespace support

2. Add removal of PvDs

3. Teach `nmcli` to manipulate provisioning domains

4. Add PvD for IPv4

5. Teach `nmcli` to manipulate network namesapces.

6. Add Python examples that use provisioning domains.

7. Add Python examples that use network name spaces.
