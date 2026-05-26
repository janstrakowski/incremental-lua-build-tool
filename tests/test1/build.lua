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
