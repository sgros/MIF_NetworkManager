# PvD and network namespace aware NetworkManager #

**WARNING: This is a very alpha quality code! Use on your own risk!**

This is a fork of [NetworkManager](http://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/)
with added support for provisioning domains as defined by [IETF MIF working group](https://datatracker.ietf.org/wg/mif/charter/).
The plan is also to add support for network namespaces in NetworkManager.

In order to test this code you'll need:

1. Patched version of [libndp](https://github.com/jpirko/libndp) library with support for
   parsing PvDs in RA messages. You can find it [here](https://github.com/sgros/MIF_libndp).

2. Modified radvd deamon that sends PvD data. You can find it [here](https://github.com/dskvorc/mif-radvd).

3. This version of NetworkManager.

## Test cases ##

### Test case 1 ###

Objective: Determine if NetworkManager, properly manages root namespace when started

Steps:

1. Start NetworkManager

Expected state:

1. In /var/run/netns there should be "rootns" file

### Test case 2 ###

Objective: Determine if NetworkManager, properly manages root namespace when stopped

Steps:

1. Stop NetworkManager using Ctrl+C

Expected state:

1. In /var/run/netns there shouldn't be "rootns" file anymore

### Test case 3 ###

Objective: Determine if NetworkManager properly creates a new network namespace

Steps:

1. Start NetworkManager

2. Invoke method over dbus to create a new network namespace:

```
dbus-send --system \
	--print-reply \
	--dest=org.freedesktop.NetworkManager \
	/org/freedesktop/NetworkManager/NetworkNamespacesController \
	org.freedesktop.NetworkManager.NetworkNamespacesController.AddNetworkNamespace \
	string:"testns"
```

Expected state:

1. The expected response from method invocation should be like follows:

```
method return time=1455099674.081185 sender=:1.1046 -> destination=:1.1050 serial=2763 reply_serial=2
   object path "/org/freedesktop/NetworkManager/NetworkNamespace/1"
```

2. In /var/run/netns there should be "testns" file

3. Enter the network namespace and check that loopback interace is present and active:

```
ip netns exec testns bash
ip addr sh
```

## TODO ##

The following items are on a todo list (in a random order):

1. Add basic network namespace support

2. Add removal of PvDs

3. Teach `nmcli` to manipulate provisioning domains

4. Add PvD for IPv4

5. Teach `nmcli` to manipulate network namesapces.

6. Add Python examples that use provisioning domains.

7. Add Python examples that use network name spaces.
