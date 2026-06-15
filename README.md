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
