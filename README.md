# Programmatic Linux (WIP)
## About (quick and dirty version edited by Gemini LLM)
Programmatic Linux (PL) is a fully reproducible Linux operating-system builder. It takes Lua code—and optionally other resources—and processes it in an isolated, deterministic environment to build an output (e.g., a complete Linux OS). Because the build environment is strictly isolated from the host system, all side-effects are eliminated. Every build is entirely deterministic: given the exact same input, it is guaranteed to produce the exact same output.

The implementation is designed to be highly performant. Written entirely in C, it completely bypasses the shell, using Lua as its sole scripting interface. It also leverages a robust caching system that stores every output indexed by a hash of its inputs. If a build is requested multiple times, only the first run is computed; subsequent runs are instantly retrieved from the cache.

The core philosophy is similar to Nix and NixOS, but it differs in several critical ways:

Language: Nix uses its own custom functional DSL for describing derivations; Programmatic Linux uses standard Lua.

Architecture: Nix relies heavily on the system shell, a massive standard environment, and a custom file hierarchy. PL is a lean, system-level C program that orchestrates the environment using only direct kernel APIs.

Portability: Nix requires a heavy installation footprint on the host device; PL can be run simply as a portable, standalone executable.
## Current state
You can build generate a directory that has 4 identical directories with hello-world file inside. It demonstrates how the cache works because each is built with the same build procedure, so the first is computed and three others are cached. You can run the example yourself:

1. Prerequisities:
You need `gcc` and `make` installed.

1. Clone this repository:
```bash
git clone https://github.com/janstrakowski/programmatic-linux.git
```

2. Enter the repo:
```bash
cd programmatic-linux
```

3. Checkout to the correct commit:
```bash
git checkout 826a838655a202dc965e7fc8543e99b0c67f5828
```

4. Fetch the git submodules:
```bash
git submodule update --init --recursive
```

5. Compile Lua:
```bash
cd lua && make
cd ..
```

6. Compile openlibm:
```bash
cd openlibm
make
cd ..
```

7. Compile the program:
```bash
bash compile.sh
```

8. Look at the build script:
Open build.lua.
```lua
local function code()
  local function dirwithhelloworldfile(dir)
    build({ dest = dir, ws = "ws" }, function()
      fs.mkdir("out")
      setdest("out")
      xio.writefile("out/helloworld.txt", "Hello, World!\n")
    end)
  end

  fs.mkdir("out")
  setdest("out")
  dirwithhelloworldfile("out/d1")
  dirwithhelloworldfile("out/d2")
  dirwithhelloworldfile("out/d3")
  dirwithhelloworldfile("out/d4")
end

local success, error = pcall(code)

if not success then
  print(error)
end
```

This is the code that builds this example. The program executes the function *code* which conntains the real logic but it needs to wrapped in a *protected enviroment* (see Lua manual or book) to catch an error if one occures. First, a directory "out" is created that will contain the output of the build (a directory containing four directories each containing a file with "Hello, World!" inside). Then there is "setdest("out")" -- it tells *Programmatic Linux* that in the place where the building process operates the output of the build will be under a path "out". When the build proccess exists *Programmatic Linux* will copy the contents of <operating_place_path>/out to a place where the cache is (<path_of_the_cache>/<sha256hash>) and from it to the destination directory given in the command-line or "pldest" by default. Then four times there is called a function "dirwithhelloworldfile" that builds the four directories with the hello-world files.

That function calls "build" which is a *sub-build* of the main build. The subbuild generated the "out" directory and "tells" *Programmatic Linux* that it is the output and creates in it the hello-world file with "Hello, World!" text inside. It is called four times: at the first time its is computed but on the second, thrird and fourth a directory with the hello-world file is already in the cache so it is just read-only mounted (not copied or linked) onto the paths "d1", "d2", "d3", "d4".

When the function we have talked about has been executed four times, then the program ends and *Programmatic Linux* copies the "out" directory into the cache and from cache copies it again to the destination directory - "pldest" by default (but -d <path> command-line option overrides that default).

9. Look a the directories in the repo:
When you run the program new ones will be created. Now when you do
```bash
ls .
```
it looks like that:
<img width="1100" height="76" alt="image" src="https://github.com/user-attachments/assets/1ca00f6a-7d00-4112-9977-6614bfe9d651" />

10. Run the program:
```bash
./program
```
It prints on the terminal:
<img width="885" height="194" alt="image" src="https://github.com/user-attachments/assets/816c0f72-c329-4633-800b-7c4d4f6ec97a" />

The program started the main build and in the main build executed four sub-builds. Looking at the durations of each build we can see that
no. 2 lasted four times longer that no. 3, 4 and 5: that is our cache in action. The first was build from the beginning to the end with our "dirwithhelloworldfile" function and the others has been copied from the cache. The whole build lasted 15ms.

11. See the result:
```bash
ls .
```
<img width="1206" height="97" alt="image" src="https://github.com/user-attachments/assets/46501b8e-7dde-4887-932d-13df24d30aab" />

Directories "pldest", "plcache" and "plworkspace" poped out. "pldest" is our destination:
```bash
ls pldest
```
<img width="587" height="39" alt="image" src="https://github.com/user-attachments/assets/0a06e480-0f49-41f8-8fa3-a25464639260" />

It contains "d1", "d2", "d3", "d4". They contain each the hello-world file:
```bash
ls pldest/d1
ls pldest/d2
ls pldest/d3
ls pldest/d4
```
<img width="584" height="153" alt="image" src="https://github.com/user-attachments/assets/d1156c5f-fad2-4800-807c-e625ee4419b3" />

Each "helloworld.txt" contains "Hello, World!":
```bash
cat pldest/d1/helloworld.txt
```
<img width="749" height="40" alt="image" src="https://github.com/user-attachments/assets/75ba7da5-6295-4fe7-9d21-891fabfdaa12" />

Everything is in its place.

12. See what's inside "plcache"
```bash
ls plcache
```
<img width="1081" height="40" alt="image" src="https://github.com/user-attachments/assets/b8ef3351-e235-4196-8ab6-6384f10dfcfd" />

There have happened two distinct builds: the main build and four subbuilds. When the build happens the input is hashed and the cache indexes the outputs of the build by those hashes: if the hash is in the cache the calling proccess uses the cache, if it is not the sub-build happens. Let us see what's inside:
```bash
ls plcache/sha256_Jk6Z8FXR9OJu1crvwGSdRdkbLHidSqHCwsyfaWCWYnM=
```
<img width="1087" height="42" alt="image" src="https://github.com/user-attachments/assets/9e9adc01-aaa7-43e2-bb46-3298b4676b80" />

It is the build that creates the hello-world file in the "out" directory.
```bash
ls plcache/sha256_Tl1GXX7STSoSCE7J0ratLbi5Wb98+jvb3WC9JyJ7fM4=
```
<img width="1151" height="40" alt="image" src="https://github.com/user-attachments/assets/74176728-8bdc-4f83-816a-256e2b947f43" />

It is the main build.

13. See what's inside "plworkspace":
```bash
ls plworkspace
```
<img width="638" height="37" alt="image" src="https://github.com/user-attachments/assets/f0d81782-c8ad-4c7a-834d-5f232783c188" />

```bash
ls plworkspace/out
```
<img width="669" height="41" alt="image" src="https://github.com/user-attachments/assets/ee395d73-0951-4ba4-bbfb-03ad4e79429c" />

```bash
ls plworkspace/ws
```
<img width="650" height="40" alt="image" src="https://github.com/user-attachments/assets/923c3471-7e61-4afc-8c5e-a793bc026f7d" />

```bash
ls plworkspace/ws/out
```
<img width="684" height="39" alt="image" src="https://github.com/user-attachments/assets/8831c1a3-4f52-4e1b-b983-781ebf5989b1" />

"plworkspace" was the place where the main build happened (well, actually the main build proccess was chrooted there). "plworkspace/ws" was the *workspace(s)* of the sub-builds (each time a build starts, the workspace is truncated).

## Contribute
(WIP)
## Donate
If you would like to support me financially, you may "Buy Me a Coffee":

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/janstrakowski)
