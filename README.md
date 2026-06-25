# Incremental Lua Build Tool
**Automate your work with Lua.**

*(This project is still in early development.)*
## About
The idea of *ILBT* is to be a simple and ergonomic framework for package management, build systems and task automation. This is going to be archieved leveraging extremally extensible and portable the [Lua](https://lua.org) programing language equipped with a comprehensive toolkit of cross-os and os-specific APIs and computation models suited for specific purposes.
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
### FS/IO libraries
At the start the host can pass pairs of names and files/directories to the script. The files will became 'file/directory' handles and directory handles are used to retrieved files.
E.g. 'stat(dir_handle, path) -> table'
```
$ binary script.lua --directory=cwd=.
print(stat(files.cwd, "hello.txt").atime) -- prints last access timestamp in milliseconds
print(stat(files.cwd, "hello.txt").kind -- prints the type of the file ("file", "directory" or "symlink")
```
## Donate
If you want to donate, I prefer just a bank transfer ([Bank Details](https://janstrakowski.github.io/jansdonations/)) or you can do via Github Sponsors.
