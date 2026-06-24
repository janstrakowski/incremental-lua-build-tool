print("--- Testing: string ---")
local str_val = "abc"
local str_ser = serialize(str_val)
print("Hex: " .. tohex(str_ser))
local str_deser = deserialize(str_ser)
print("Deser string: " .. tostring(str_deser))
print("Valid: " .. tostring(str_deser == str_val))

print("\n--- Testing: nil ---")
local nil_ser = serialize(nil)
print("Hex: " .. tohex(nil_ser))
local nil_deser = deserialize(nil_ser)
print("Deser nil: " .. tostring(nil_deser))
print("Valid: " .. tostring(nil_deser == nil))

print("\n--- Testing: table ---")
-- Note: In Lua, assigning `c = nil` inside a table literal means the key `c` is not added to the table.
local tbl_val = {abc = 123, b1 = { a1 = true, b2 = false, b3 = 0.123 }, c = nil}
local tbl_ser = serialize(tbl_val)
print("Hex: " .. tohex(tbl_ser))
local tbl_deser = deserialize(tbl_ser)

-- We access keys explicitly to ensure deterministic stdout for testing purposes
print("Deser tbl_deser.abc: " .. tostring(tbl_deser.abc))
print("Deser tbl_deser.b1.a1: " .. tostring(tbl_deser.b1.a1))
print("Deser tbl_deser.b1.b2: " .. tostring(tbl_deser.b1.b2))
print("Deser tbl_deser.b1.b3: " .. tostring(tbl_deser.b1.b3))
print("Deser tbl_deser.c: " .. tostring(tbl_deser.c))

local table_valid = (tbl_deser.abc == 123) 
                and (tbl_deser.b1.a1 == true) 
                and (tbl_deser.b1.b2 == false) 
                and (tbl_deser.b1.b3 == 0.123) 
                and (tbl_deser.c == nil)
print("Valid: " .. tostring(table_valid))

print("\n--- Testing: function ---")
local fn_val = function(a,b) return a + b end
local fn_ser = serialize(fn_val)
print("Hex: " .. tohex(fn_ser))
local fn_deser = deserialize(fn_ser)

-- Execute the deserialized bytecode to validate it retained its logic
local fn_result = fn_deser(10, 25)
print("Deser function execution (10 + 25): " .. tostring(fn_result))
print("Valid: " .. tostring(fn_result == 35))

print("\nDone.")
