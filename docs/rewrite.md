# Rewrite summary

**NOTE**: The public API of `getmac` is **unchanged** as part of this rewrite. `get_mac_address()` is still the primary way of getting a MAC address, it's just the "under the hood" internals that have changed completely.

## Motivation
The current system of finding a MAC is, to put it bluntly, throw commands at the wall, see if they stick, and promptly forget what stuck for next time. While this *has* worked up till now, it's a hack built on hacks and has needed a rewrite for a while. It's prone to false-positives (multiple nasty bugs were caused by this), is quite slow ("misses" can take *seconds* to return!), extremely difficult to test (and thus aforementioned bugs were missed), and is generally a unreadable pile of spaghetti to anyone except me.

## Rewrite
The rewrite is built from the ground up as a class-based modular architecture. Each "method" (a way of getting a MAC) is implemented as a subclass of the `Method` base class. The methods define what platforms they apply to (`platforms`, e.g. `platforms = {"windows", "wsl"}`), the type of method (`method_type`, e.g. `method_type = "ip4"`) and other attributes, such as if they make a network request as part of the check (`net_request`).

There are two functions that are implemented by `Method` subclasses: `test()` and `get(arg)`. The `test()` functions implements a *fast* test for the feasibility of the method, e.g. checking if the `/proc/net/arp` file exists for the `ArpFile` method. The `get(arg)` functions implements the actual functionality of looking up the MAC, e.g. in the case of `ArpFile`, parsing the contents of `/proc/net/arp`.

When `get_mac_address()` is called for the first time for a particular method type (e.g. `"iface"`), a cache is initialized for that method type (in `initialize_method_cache()`):
1. Create a list of all methods
2. Remove any that don't apply to the current platform (e.g. `"windows"`)
3. Remove any that don't apply to this method type (`"iface"`)
4. Test all methods by calling `test()` and remove any that fail (return `False`)
5. Store any methods that remain in the cache for this method type (`"iface"`)

The first of the methods in the cache is used to fulfill the `get_mac_address()` via a call to `get(arg)` on the method. If there's a critical failure during the `get()`, then the method is marked as unusable, removed from the cache, and the next method in the cache is used instead. Some methods can't be tested reliably without starting a process, which is expensive, so instead we fail them on first attempt. Calling a single method addresses the old system's issue of trying every method until there was a success, which led to "misses" (no MAC available for whatever was requested) taking several seconds (or longer in extreme cases).

## Benefits
The new system has a number of benefits
- Reduction of false-positives and false-negatives by improving method selection accuracy (platform, validity, etc.)
- *Significantly* faster overall
- "Misses" have the same performance as "Hits"
- Easier to test, since each method can be tested directly via it's class
- Easier to type annotate and analyze with mypy
- Easier to read, improving reviewability and ease of contributing for newcomers
- Extensible! Custom methods can be defined and added at runtime (which is perfect if you have some particular edge case but aren't able to open-source it).
