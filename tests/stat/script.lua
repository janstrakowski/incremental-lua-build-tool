-- test_stat.lua

-- Iterate over all handles injected by Zig
for name, handle in pairs(files) do
    print("--- Checking handle: " .. name .. " ---")
    
    -- The stat function is registered in fs.zig 
    -- It requires a directory handle 
    local success, result = pcall(stat, handle, "hello.txt")
    
    if success then
        print("Kind: " .. result.kind)
        print("Size: " .. result.size)
        print("Atime: " .. result.atime)
        print("Mtime: " .. result.mtime)
    else
        print("Stat failed for 'hello.txt' in " .. name .. ": " .. result)
    end
end
