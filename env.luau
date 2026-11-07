local script_env = getfenv(0)
local tea = script_env.tea or {}

local old_mt = getmetatable(script_env)
local old_index = if type(old_mt) == "table" then old_mt.__index else nil
local new_mt = {}

if type(old_mt) == "table" then
    for key, value in pairs(old_mt) do
        new_mt[key] = value
    end
end

new_mt.__index = function(_, key)
    local value = rawget(tea, key)
    if value ~= nil then
        return value
    end

    if type(old_index) == "function" then
        return old_index(script_env, key)
    end
    if type(old_index) == "table" then
        return old_index[key]
    end
    return nil
end

setmetatable(script_env, new_mt)
rawset(script_env, "tea", tea)
rawset(script_env, "_G", tea)

function tea.identifyexecutor()
    return "Tea", "2.0.0"
end

tea.getexecutorname = tea.identifyexecutor

function tea.getgenv()
    return tea
end

function tea.httpget(url)
    assert(type(tea_http_fingerprint) == "string" and #tea_http_fingerprint > 0, "httpget: fingerprint is not initialized")
    local response = tea.request({
        Url = url,
        Method = "GET",
        Headers = {
            ["Exploit-Guid"] = tea_http_fingerprint,
            Fingerprint = tea_http_fingerprint,
            Accept = "*/*",
        },
    })
    if not response.Success then
        error("httpget: HTTP " .. response.StatusCode, 2)
    end
    return response.Body
end

local unsafe_game_methods = {
    ["Load"] = true,
    ["OpenScreenshotsFolder"] = true,
    ["OpenVideosFolder"] = true,
    ["AddCoreScriptLocal"] = true,
    ["SaveScriptProfilingData"] = true,
    ["GetRobuxBalance"] = true,
    ["PerformPurchase"] = true,
    ["PerformPurchaseV2"] = true,
    ["PerformBulkPurchase"] = true,
    ["PerformSubscriptionPurchase"] = true,
    ["PerformSubscriptionPurchaseV2"] = true,
    ["PerformCancelSubscription"] = true,
    ["PromptPurchase"] = true,
    ["PromptProductPurchase"] = true,
    ["PromptGamePassPurchase"] = true,
    ["PromptBundlePurchase"] = true,
    ["PromptBulkPurchase"] = true,
    ["PromptRobloxPurchase"] = true,
    ["PromptThirdPartyPurchase"] = true,
    ["PromptPremiumPurchase"] = true,
    ["PromptSubscriptionPurchase"] = true,
    ["PromptCancelSubscription"] = true,
    ["PromptNativePurchase"] = true,
    ["PromptNativePurchaseWithLocalPlayer"] = true,
    ["PromptCollectiblesPurchase"] = true,
    ["PrepareCollectiblesPurchase"] = true,
    ["GetUserSubscriptionPaymentHistoryAsync"] = true,
    ["GetUserSubscriptionDetailsInternalAsync"] = true,
    ["GetUserSubscriptionStatusAsync"] = true,
    ["ReportAbuse"] = true,
    ["ReportAbuseV3"] = true,
    ["TakeScreenshot"] = true,
    ["ToggleRecording"] = true,
    ["OpenBrowserWindow"] = true,
    ["OpenNativeOverlay"] = true,
    ["ExecuteJavaScript"] = true,
    ["ReturnToJavaScript"] = true,
    ["SendCommand"] = true,
    ["EmitHybridEvent"] = true,
    ["OpenWeChatAuthWindow"] = true,
    ["BroadcastNotification"] = true,
    ["SetPurchasePromptIsShown"] = true,
    ["OpenUrl"] = true,
    ["DetectUrl"] = true,
    ["RegisterLuaUrl"] = true,
    ["StartLuaUrlDelivery"] = true,
    ["StopLuaUrlDelivery"] = true,
    ["SwitchToSettingsApp"] = true,
    ["SupportsSwitchToSettingsApp"] = true,
    ["GetLastLuaUrl"] = true,
    ["GetAndClearLastPendingUrl"] = true,
    ["IsUrlRegistered"] = true,
    ["RequestInternal"] = true,
    ["RequestAsync"] = true,
    ["GetAsync"] = true,
    ["PostAsync"] = true,
    ["GetAsyncFullUrl"] = true,
    ["PostAsyncFullUrl"] = true,
    ["RequestLimitedAsync"] = true,
    ["HttpRequestAsync"] = true,
    ["GetApiV1"] = true,
    ["InvokeAsync"] = true,
    ["RegisterOpenCloud"] = true,
    ["CaptureScreenshot"] = true,
    ["CreatePostAsync"] = true,
    ["DeleteCapture"] = true,
    ["DeleteCapturesAsync"] = true,
    ["GetCaptureFilePathAsync"] = true,
    ["GetCaptureUploadDataAsync"] = true,
    ["GetCaptureSizeAsync"] = true,
    ["GetCaptureStorageSizeAsync"] = true,
    ["RetrieveCaptures"] = true,
    ["SaveCaptureToExternalStorage"] = true,
    ["SaveCapturesToExternalStorageAsync"] = true,
    ["SaveScreenshotCapture"] = true,
    ["PromptSaveCapturesToGallery"] = true,
    ["PromptShareCapture"] = true,
    ["Call"] = true,
    ["GetLast"] = true,
    ["GetMessageId"] = true,
    ["GetProtocolMethodRequestMessageId"] = true,
    ["GetProtocolMethodResponseMessageId"] = true,
    ["MakeRequest"] = true,
    ["Publish"] = true,
    ["PublishProtocolMethodRequest"] = true,
    ["PublishProtocolMethodResponse"] = true,
    ["Subscribe"] = true,
    ["SubscribeToProtocolMethodRequest"] = true,
    ["SubscribeToProtocolMethodResponse"] = true,
    ["GetCredentialsHeaders"] = true,
    ["GetDeviceAccessToken"] = true,
    ["GetDeviceIntegrityToken"] = true,
    ["GetDeviceIntegrityTokenYield"] = true,
    ["NoPromptCreateOutfit"] = true,
    ["NoPromptDeleteOutfit"] = true,
    ["NoPromptRenameOutfit"] = true,
    ["NoPromptSaveAvatar"] = true,
    ["NoPromptSaveAvatarThumbnailCustomization"] = true,
    ["NoPromptSetFavorite"] = true,
    ["NoPromptUpdateOutfit"] = true,
    ["PerformCreateOutfitWithDescription"] = true,
    ["PerformDeleteOutfit"] = true,
    ["PerformRenameOutfit"] = true,
    ["PerformSaveAvatarWithDescription"] = true,
    ["PerformSetFavorite"] = true,
    ["PerformUpdateOutfit"] = true,
    ["PromptCreateOutfit"] = true,
    ["PromptDeleteOutfit"] = true,
    ["PromptRenameOutfit"] = true,
    ["PromptSaveAvatar"] = true,
    ["PromptSetFavorite"] = true,
    ["PromptUpdateOutfit"] = true,
    ["SetAllowInventoryReadAccess"] = true,
    ["PromptAllowInventoryReadAccess"] = true,
    ["SignalCreateOutfitFailed"] = true,
    ["SignalCreateOutfitPermissionDenied"] = true,
    ["SignalDeleteOutfitFailed"] = true,
    ["SignalDeleteOutfitPermissionDenied"] = true,
    ["SignalRenameOutfitFailed"] = true,
    ["SignalRenameOutfitPermissionDenied"] = true,
    ["SignalSaveAvatarPermissionDenied"] = true,
    ["SignalSetFavoriteFailed"] = true,
    ["SignalSetFavoritePermissionDenied"] = true,
    ["SignalUpdateOutfitFailed"] = true,
    ["SignalUpdateOutfitPermissionDenied"] = true,
    ["GetLocalFileContents"] = true,
    ["SetBaseUrl"] = true,
    ["FetchAssetWithFormat"] = true,
    ["RegisterUGCValidationFunction"] = true,
    ["PerformManagedUpdate"] = true,
    ["TestService.Run"] = true,
    ["TestService"] = true,
    ["Run"] = true,
}

local function blocked_game_member(key)
    if type(key) ~= "string" then
        return
    end
    for index = 1, #key - 3 do
        local a, b, c, d = string.byte(key, index, index + 3)
        if a == 0xF0 and b >= 0x90 and b <= 0x9F and c >= 0x80 and c <= 0xBF and d >= 0x80 and d <= 0xBF then
            error("Blocked: vulnerable character detected", 3)
        end
    end
    if unsafe_game_methods[key] then
        error("Function '" .. key .. "' has been blocked for security reasons", 3)
    end
end

tea.__blocked_game_member = blocked_game_member

local function make_game_access(real_game)
    local function httpget_unbound(self, url, ...)
        assert(self == real_game, "HttpGet: expected DataModel as self")
        return tea.httpget(url, ...)
    end
    local function game_index(key)
        blocked_game_member(key)
        if key == "HttpGet" or key == "HttpGetAsync" then
            return httpget_unbound
        end
        return real_game[key]
    end
    return httpget_unbound, game_index
end
tea.__httpget_unbound, tea.__game_index = make_game_access(game)

local function make_http_index(real_game, original_typeof)
    return function(object, key)
        if original_typeof(object) == "Instance" and object == real_game then
            return tea.__game_index(key)
        end
        return object[key]
    end
end
rawset(script_env, "__tea_http_index", make_http_index(game, typeof))

tea.__load_pending = {}
function tea.loadstring(source, chunkname)
    assert(type(source) == "string", "loadstring: expected source string")
    assert(chunkname == nil or type(chunkname) == "string", "loadstring: expected chunk name string")
    chunkname = chunkname or "=loadstring"
    if #source > 10 * 1024 * 1024 then
        return nil, "loadstring: source exceeds 10 MiB"
    end
    if #chunkname > 256 or chunkname:find("\0", 1, true) then
        return nil, "loadstring: invalid chunk name"
    end

    local environment = getfenv(2)
    local http_service = game:GetService("HttpService")
    local id = http_service:GenerateGUID(false)
    local pending = tea.__load_pending
    pending[id] = false
    local function hex(value)
        return (value:gsub(".", function(byte)
            return string.format("%02x", string.byte(byte))
        end))
    end
    local created, request = pcall(function()
        return http_service:RequestInternal({
            Url = "http://127.0.0.1:6969/load/" .. tea_http_token .. "/" .. id .. "/" .. hex(chunkname),
            Method = "POST",
            Body = source,
        })
    end)
    if not created then
        pending[id] = nil
        return nil, "loadstring: " .. tostring(request)
    end

    local finished = false
    local success = false
    local response = nil
    local started, start_error = pcall(function()
        request:Start(function(ok, result)
            success = ok
            response = result
            finished = true
        end)
    end)
    if not started then
        pending[id] = nil
        return nil, "loadstring: " .. tostring(start_error)
    end

    local deadline = os.clock() + 120
    while not finished and os.clock() < deadline do
        task.wait()
    end
    if not finished then
        pending[id] = nil
        return nil, "loadstring: compiler request timed out"
    end
    if not success or type(response) ~= "table" or response.StatusCode ~= 200 then
        pending[id] = nil
        return nil, "loadstring: " .. (type(response) == "table" and tostring(response.Body) or "compiler request failed")
    end
    while pending[id] == false and os.clock() < deadline do
        task.wait()
    end
    local result = pending[id]
    pending[id] = nil
    if result == false or result == nil then
        return nil, "loadstring: compiled function was not delivered"
    end
    if result.error then
        return nil, result.error
    end
    setfenv(result.fn, environment)
    return result.fn
end
rawset(script_env, "loadstring", tea.loadstring)

function tea.request(options)
    assert(type(options) == "table", "request: expected table")
    local url = options.Url
    assert(type(url) == "string" and #url > 0 and #url <= 4096, "request: expected a URL string up to 4096 bytes")
    assert(url:sub(1, 7) == "http://" or url:sub(1, 8) == "https://", "request: expected http:// or https://")
    assert(options.Method == nil or type(options.Method) == "string", "request: expected Method string")
    assert(options.Headers == nil or type(options.Headers) == "table", "request: expected Headers table")
    assert(options.Body == nil or type(options.Body) == "string", "request: expected Body string")
    local body = options.Body or ""
    assert(#body <= 10 * 1024 * 1024, "request: body exceeds 10 MiB")

    local function field(value)
        return tostring(#value) .. "\n" .. value
    end
    local headers = {}
    local count = 0
    local header_size = 0
    for name, value in pairs(options.Headers or {}) do
        assert(type(name) == "string" and type(value) == "string", "request: header names and values must be strings")
        count += 1
        header_size += #name + #value + 24
        assert(count <= 128 and header_size <= 60000, "request: headers too large")
        table.insert(headers, field(name))
        table.insert(headers, field(value))
    end
    local payload = field(url) .. field((options.Method or "GET"):upper()) .. field(tostring(count)) .. table.concat(headers) .. field(body)
    local handle = game:GetService("HttpService"):RequestInternal({
        Url = "http://127.0.0.1:6969/http/" .. tea_http_token,
        Method = "POST",
        Body = payload,
    })
    local done = false
    local success = false
    local response = nil
    handle:Start(function(ok, result)
        success = ok
        response = result
        done = true
    end)
    local deadline = os.clock() + 120
    while not done and os.clock() < deadline do
        task.wait()
    end
    if not done then
        error("request: request timed out", 2)
    end
    if type(response) ~= "table" or type(response.Body) ~= "string" then
        error("request: invalid bridge response", 2)
    end
    if not success or response.StatusCode ~= 200 then
        error(response.Body ~= "" and response.Body or "request: HTTP bridge failed", 2)
    end

    local wire = response.Body
    local position = 1
    local function read_field(limit)
        local finish = wire:find("\n", position, true)
        if not finish or finish - position > 10 then
            error("request: invalid response frame", 2)
        end
        local length = tonumber(wire:sub(position, finish - 1))
        if not length or length < 0 or length % 1 ~= 0 or length > limit or finish + length > #wire then
            error("request: invalid response field", 2)
        end
        local value = wire:sub(finish + 1, finish + length)
        position = finish + length + 1
        return value
    end
    local status = tonumber(read_field(3))
    local message = read_field(4096)
    local header_count = tonumber(read_field(5))
    if not status or status < 100 or status > 599 or not header_count or header_count < 0
        or header_count % 1 ~= 0 or header_count > 8192 then
        error("request: invalid response status or headers", 2)
    end
    local response_headers = {}
    for _ = 1, header_count do
        local name = read_field(16384)
        local value = read_field(131072)
        response_headers[name] = response_headers[name] and response_headers[name] .. ", " .. value or value
    end
    local response_body = read_field(10 * 1024 * 1024)
    if position ~= #wire + 1 then
        error("request: trailing response data", 2)
    end
    return {
        Success = status >= 200 and status < 300,
        StatusCode = status,
        StatusMessage = message,
        Headers = response_headers,
        Body = response_body,
    }
end

local function misc_request(operation, payload)
    local handle = game:GetService("HttpService"):RequestInternal({
        Url = "http://127.0.0.1:6969/misc/" .. tea_http_token .. "/" .. operation,
        Method = "POST",
        Body = payload,
    })
    local done = false
    local success = false
    local response = nil
    handle:Start(function(ok, result)
        success = ok
        response = result
        done = true
    end)
    local deadline = os.clock() + 120
    while not done and os.clock() < deadline do
        task.wait()
    end
    if not done then
        error(operation .. ": request timed out", 3)
    end
    if type(response) ~= "table" or type(response.Body) ~= "string" then
        error(operation .. ": invalid bridge response", 3)
    end
    if not success or response.StatusCode ~= 200 then
        error(response.Body ~= "" and response.Body or operation .. ": bridge failed", 3)
    end
    return response.Body
end

function tea.lz4compress(data)
    assert(type(data) == "string" and #data <= 10 * 1024 * 1024, "lz4compress: expected string up to 10 MiB")
    return misc_request("lz4compress", data)
end

function tea.lz4decompress(data, size)
    assert(type(data) == "string", "lz4decompress: expected string")
    assert(type(size) == "number" and size >= 0 and size <= 10 * 1024 * 1024 and size % 1 == 0, "lz4decompress: expected uncompressed size up to 10 MiB")
    return misc_request("lz4decompress", tostring(size) .. "\n" .. data)
end

function tea.setclipboard(text)
    assert(type(text) == "string", "expected string")
    misc_request("setclipboard", text)
end

function tea.setfpscap(fps)
    assert(type(fps) == "number" and fps == fps and fps >= 0 and fps < math.huge, "setfpscap: expected a non negative non infinite number for FPS")
    misc_request("setfpscap", string.format("%.17g", fps))
end

for _, name in ipairs({ "identifyexecutor", "request", "httpget", "getgenv", "getexecutorname", "loadstring", "lz4compress", "lz4decompress", "setclipboard", "setfpscap" }) do
    rawset(script_env, name, tea[name])
end
