# Incremental Lua Build Tool
**Status: Work in Progress**
## About
*ILBT* is a binary that lets you run [Lua](https://lua.org) code (extremely simple programming language) that can spawn asynchonous tasks running pieces of *Lua* code that have no I/O (they receive an arbitrary *Lua* value one-time as the input, they execute the piece of code and eventually they return an arbitrary *Lua* value as the ouput).
The input, the code and the output all can be serialised (making it for example possible to send them anywhere).
*Lua* is a fully-blown programming language so the *ILBT* programming framework can arm the build tasks with any sophisticated feature the running operating system provides (for example running Linux containers).

### Applications I can imagine:
- (multi-platform) (distributed) build systems,
- single-source-of-truth (incrementally-generated) Linux distributions,
- remote Linux system setup,
- automatic embeded systems setup.

### Possible advantages/disadvantages
*You can compare to [Nix(OS)](https://nixos.org/) or [Bazel](https://bazel.build/) or even [Ansible](https://www.redhat.com/en/ansible-collaborative) or [Terraform](https://developer.hashicorp.com/terraform) for remote Linux/infrastructure setup.*
#### Advantages:
- the simplicity, portability and low barrier of entry of *Lua* programming language,
- multi-platform design.
#### Disadvatages:
- imperative computing model,
- interpreted programming language performance bottleneck,
- absence of community libraries.
## Current Progress
### Sha256 hashing facility
You can hash an arbitrary Lua value with SHA256 algorithms using 'sha256(value)' Lua function:
```lua
print("hash.lua")
print("\"abc\"")
print(tohex(sha256("abc")))
print("nil")
print(tohex(sha256(nil)))
print("{abc = 123, b1 = { a1 = true, b2 = false, b3 = 0.123 }, c = nil}")
print(tohex(sha256({abc = 123, b1 = { a1 = true, b2 = false, b3 = 0.123 }, c = nil})))
print("Done.")
```
Doing `zig build run -- tests/hash.lua` results in:
```
hash.lua
"abc"
c8961b21b2ee347d6fae91d71653ab8f3a5b53eb9dea9ce2adc724ddb5096ec5
nil
6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
{abc = 123, b1 = { a1 = true, b2 = false, b3 = 0.123 }, c = nil}
9f5dc91750826544ba017d035f4a1b2135be1fee41c19d67cac9126320af5961
Done.
```
### Serialization/Deserialization facility
You can serialize/deserialize arbitrary Lua values. Two functions are provided:
`serialize(value) -> binary string` and `deserialize(binary string) -> value`.
Functions are not excempted.
