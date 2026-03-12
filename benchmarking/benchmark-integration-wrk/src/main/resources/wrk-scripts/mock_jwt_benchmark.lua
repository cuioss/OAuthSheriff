-- Optimized WRK script for Mock JWT validation benchmark
-- Identical to jwt_benchmark.lua but targets /mock-jwt/validate endpoint
-- Purpose: Measure CDI/serialization overhead without JWT library validation

-- Token pool (loaded at module initialization, no file I/O)
local tokens = {}

-- Thread-local variables (initialized in init())
local thread_id = 0
local thread_token_index = 0
local thread_request_count = 0
local thread_success_count = 0
local thread_error_count = 0
local thread_unauthorized_count = 0

-- Load tokens from environment or use dynamic generation
local function load_tokens()
    -- Option 1: Try to load from TOKEN_DATA environment variable (base64 encoded tokens separated by newlines)
    local token_data = os.getenv("TOKEN_DATA")
    if token_data then
        -- Decode base64 if needed
        for token in token_data:gmatch("[^\n]+") do
            table.insert(tokens, token)
        end
        print(string.format("Loaded %d tokens from environment", #tokens))
        return
    end

    -- Option 2: Generate mock tokens for testing (when real tokens not available)
    -- This is just for fallback - real tokens should be provided via TOKEN_DATA
    local token_count = tonumber(os.getenv("TOKEN_COUNT") or "100")
    print(string.format("WARNING: Using mock tokens (count=%d). For real benchmarks, provide TOKEN_DATA.", token_count))

    -- Generate deterministic mock tokens
    for i = 1, token_count do
        -- Create a mock JWT-like token structure
        local header = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtb2NrIn0"
        local payload = "eyJleHAiOjE3MzAwMDAwMDAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoibW9jay0" .. tostring(i) .. "Iiwic3ViIjoiYmVuY2htYXJrLXVzZXIiLCJhenAiOiJiZW5jaG1hcmstY2xpZW50In0"
        local signature = string.rep("x", 342) -- Mock signature
        table.insert(tokens, header .. "." .. payload .. "." .. signature)
    end
end

-- Initialize tokens once at module load (shared across all threads)
load_tokens()

-- Validate we have tokens
if #tokens == 0 then
    error("FATAL: No tokens available. Set TOKEN_DATA environment variable with tokens.")
end

-- WRK setup function - called once per thread before init
function setup(thread)
    thread:set("id", thread.id)
    return thread
end

-- WRK init function - called once per thread
function init(args)
    -- Initialize thread-local variables
    thread_id = tonumber(id) or 0
    -- Distribute starting indices across threads to avoid initial contention
    thread_token_index = (thread_id % #tokens)
    thread_request_count = 0
    thread_success_count = 0
    thread_error_count = 0
    thread_unauthorized_count = 0
end

-- WRK request function - called for each request
function request()
    -- Round-robin through tokens (thread-local index)
    thread_token_index = (thread_token_index % #tokens) + 1
    local token = tokens[thread_token_index]

    -- Track request count
    thread_request_count = thread_request_count + 1

    -- Build optimized request (minimize allocations)
    wrk.method = "POST"
    wrk.path = "/mock-jwt/validate"
    wrk.headers["Authorization"] = "Bearer " .. token
    wrk.headers["Content-Type"] = "application/json"
    wrk.headers["Accept"] = "application/json"
    wrk.headers["Connection"] = "keep-alive"

    return wrk.format(nil, nil, nil, "")
end

-- WRK response function - called for each response
function response(status, headers, body)
    if status == 200 or status == 201 then
        thread_success_count = thread_success_count + 1
    elseif status == 401 or status == 403 then
        thread_unauthorized_count = thread_unauthorized_count + 1
        -- Only log first unauthorized per thread to reduce overhead
        if thread_unauthorized_count == 1 then
            print(string.format("[Thread %d] Token expiration detected", thread_id))
        end
    else
        thread_error_count = thread_error_count + 1
        -- Log first few errors per thread
        if thread_error_count <= 3 then
            print(string.format("[Thread %d] Error: HTTP %d", thread_id, status))
        end
    end
end

-- WRK done function - called when benchmark completes
-- Removed custom output to avoid duplication with WRK's native output
-- WRK already provides all the necessary statistics
