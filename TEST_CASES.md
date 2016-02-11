# Test cases #

## Management of network namespaces ##

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

## Management of provisioning domains ##

