# Incremental Lua Build Tool
**Status: Work in Progress**
## About
*ILBT* is going to be a one-binary [Lua](https://lua.org) virtual machine running on Linux and Windows that can call coroutines (the "builds") that have their resources restricted only to the explicitly given at the call.
The *builds* are cached by their input data so that the computation has only to happen at the first call and the inputs are completely serialisable so that the build can be delegated to a different process or even machine.

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
