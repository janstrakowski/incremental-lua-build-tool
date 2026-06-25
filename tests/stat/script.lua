-- test_stat.lua

-- Iterate over all handles injected by Zig
for _, arg in ipairs(args) do
    local handle_name, path = string.match(arg, "([^:]+):([^:]+)")
    print("--- Checking handle '" .. handle_name .. "' -> '" .. path .. "'.  ---")
    
    -- The stat function is registered in fs.zig 
    -- It requires a directory handle 
    local success, result = pcall(stat, files[handle_name], path)
    
    if success then
        print("Kind: " .. result.kind)
        print("Size: " .. result.size)
        print("Mtime: " .. result.mtime)
    else
        print("Stat failed for 'hello.txt' in " .. name .. ": " .. result)
    end
end
