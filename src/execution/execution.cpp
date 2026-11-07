#include "execution.h"
#include "src/signer/signer_api.h"

#include <Luau/Allocator.h>
#include <Luau/Ast.h>
#include <Luau/Lexer.h>
#include <Luau/Parser.h>

#include <algorithm>
#include <cstring>
#include <utility>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace
{
    bool blocked_game_method(std::string_view name)
    {
        static const std::unordered_set<std::string_view> names = {
            "Load", "OpenScreenshotsFolder", "OpenVideosFolder", "AddCoreScriptLocal",
            "SaveScriptProfilingData", "GetRobuxBalance", "PerformPurchase", "PerformPurchaseV2",
            "PerformBulkPurchase", "PerformSubscriptionPurchase", "PerformSubscriptionPurchaseV2", "PerformCancelSubscription",
            "PromptPurchase", "PromptProductPurchase", "PromptGamePassPurchase", "PromptBundlePurchase",
            "PromptBulkPurchase", "PromptRobloxPurchase", "PromptThirdPartyPurchase", "PromptPremiumPurchase",
            "PromptSubscriptionPurchase", "PromptCancelSubscription", "PromptNativePurchase", "PromptNativePurchaseWithLocalPlayer",
            "PromptCollectiblesPurchase", "PrepareCollectiblesPurchase", "GetUserSubscriptionPaymentHistoryAsync", "GetUserSubscriptionDetailsInternalAsync",
            "GetUserSubscriptionStatusAsync", "ReportAbuse", "ReportAbuseV3", "TakeScreenshot",
            "ToggleRecording", "OpenBrowserWindow", "OpenNativeOverlay", "ExecuteJavaScript",
            "ReturnToJavaScript", "SendCommand", "EmitHybridEvent", "OpenWeChatAuthWindow",
            "BroadcastNotification", "SetPurchasePromptIsShown", "OpenUrl", "DetectUrl",
            "RegisterLuaUrl", "StartLuaUrlDelivery", "StopLuaUrlDelivery", "SwitchToSettingsApp",
            "SupportsSwitchToSettingsApp", "GetLastLuaUrl", "GetAndClearLastPendingUrl", "IsUrlRegistered",
            "RequestInternal", "RequestAsync", "GetAsync", "PostAsync",
            "GetAsyncFullUrl", "PostAsyncFullUrl", "RequestLimitedAsync", "HttpRequestAsync",
            "GetApiV1", "InvokeAsync", "RegisterOpenCloud", "CaptureScreenshot",
            "CreatePostAsync", "DeleteCapture", "DeleteCapturesAsync", "GetCaptureFilePathAsync",
            "GetCaptureUploadDataAsync", "GetCaptureSizeAsync", "GetCaptureStorageSizeAsync", "RetrieveCaptures",
            "SaveCaptureToExternalStorage", "SaveCapturesToExternalStorageAsync", "SaveScreenshotCapture", "PromptSaveCapturesToGallery",
            "PromptShareCapture", "Call", "GetLast", "GetMessageId",
            "GetProtocolMethodRequestMessageId", "GetProtocolMethodResponseMessageId", "MakeRequest", "Publish",
            "PublishProtocolMethodRequest", "PublishProtocolMethodResponse", "Subscribe", "SubscribeToProtocolMethodRequest",
            "SubscribeToProtocolMethodResponse", "GetCredentialsHeaders", "GetDeviceAccessToken", "GetDeviceIntegrityToken",
            "GetDeviceIntegrityTokenYield", "NoPromptCreateOutfit", "NoPromptDeleteOutfit", "NoPromptRenameOutfit",
            "NoPromptSaveAvatar", "NoPromptSaveAvatarThumbnailCustomization", "NoPromptSetFavorite", "NoPromptUpdateOutfit",
            "PerformCreateOutfitWithDescription", "PerformDeleteOutfit", "PerformRenameOutfit", "PerformSaveAvatarWithDescription",
            "PerformSetFavorite", "PerformUpdateOutfit", "PromptCreateOutfit", "PromptDeleteOutfit",
            "PromptRenameOutfit", "PromptSaveAvatar", "PromptSetFavorite", "PromptUpdateOutfit",
            "SetAllowInventoryReadAccess", "PromptAllowInventoryReadAccess", "SignalCreateOutfitFailed", "SignalCreateOutfitPermissionDenied",
            "SignalDeleteOutfitFailed", "SignalDeleteOutfitPermissionDenied", "SignalRenameOutfitFailed", "SignalRenameOutfitPermissionDenied",
            "SignalSaveAvatarPermissionDenied", "SignalSetFavoriteFailed", "SignalSetFavoritePermissionDenied", "SignalUpdateOutfitFailed",
            "SignalUpdateOutfitPermissionDenied", "GetLocalFileContents", "SetBaseUrl", "FetchAssetWithFormat",
            "RegisterUGCValidationFunction", "PerformManagedUpdate", "TestService.Run", "TestService",
            "Run",
        };
        return names.contains(name);
    }
}

std::string game_httpget(const std::string& source)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseResult parsed = Luau::Parser::parse(source.c_str(), source.size(), names, allocator);
    if (!parsed.errors.empty())
        return source;

    struct bindings_t : Luau::AstVisitor
    {
        std::unordered_map<Luau::AstLocal*, Luau::AstExpr*> initializers;
        std::unordered_set<Luau::AstLocal*> written;
        std::unordered_set<Luau::AstExpr*> targets;

        void assign(Luau::AstExpr* expr)
        {
            targets.insert(expr);
            if (auto* local = expr->as<Luau::AstExprLocal>())
                written.insert(local->local);
        }

        bool visit(Luau::AstStatLocal* stat) override
        {
            for (size_t i = 0; i < (std::min)(stat->vars.size, stat->values.size); ++i)
                initializers.emplace(stat->vars.data[i], stat->values.data[i]);
            return true;
        }

        bool visit(Luau::AstStatAssign* stat) override
        {
            for (auto* target : stat->vars)
                assign(target);
            return true;
        }

        bool visit(Luau::AstStatCompoundAssign* stat) override
        {
            assign(stat->var);
            return true;
        }

        bool visit(Luau::AstStatFunction* stat) override
        {
            auto* target = stat->name;
            while (auto* member = target->as<Luau::AstExprIndexName>())
            {
                targets.insert(target);
                target = member->expr;
            }
            if (target == stat->name)
                assign(target);
            return true;
        }

        bool is_game(Luau::AstExpr* expr, std::unordered_set<Luau::AstLocal*>& seen) const
        {
            if (auto* group = expr->as<Luau::AstExprGroup>())
                return is_game(group->expr, seen);
            if (auto* global = expr->as<Luau::AstExprGlobal>())
                return global->name.value &&
                (std::strcmp(global->name.value, "game") == 0 || std::strcmp(global->name.value, "Game") == 0);
            auto* local = expr->as<Luau::AstExprLocal>();
            if (!local || written.contains(local->local) || !seen.insert(local->local).second)
                return false;
            auto found = initializers.find(local->local);
            return found != initializers.end() && is_game(found->second, seen);
        }

        bool is_game(Luau::AstExpr* expr) const
        {
            std::unordered_set<Luau::AstLocal*> seen;
            return is_game(expr, seen);
        }
    } bindings;
    parsed.root->visit(&bindings);

    std::vector<size_t> lines{ 0 };
    for (size_t i = 0; i < source.size(); ++i)
        if (source[i] == '\n')
            lines.push_back(i + 1);

    struct edit_t
    {
        size_t begin;
        size_t end;
        std::string replacement;
        size_t order;
    };

    struct visitor_t : Luau::AstVisitor
    {
        const std::string& source;
        const std::vector<size_t>& lines;
        const bindings_t& bindings;
        std::vector<edit_t> edits;

        visitor_t(const std::string& source, const std::vector<size_t>& lines, const bindings_t& bindings) : source(source), lines(lines), bindings(bindings) {}

        size_t offset(const Luau::Position& position) const
        {
            if (position.line >= lines.size())
                throw std::runtime_error("HttpGet source line out of range");
            const size_t result = lines[position.line] + position.column;
            if (result > source.size())
                throw std::runtime_error("HttpGet source position out of range");
            return result;
        }

        void edit(size_t begin, size_t end, std::string replacement, bool lines_before = false, bool group_lines = false)
        {
            if (begin > end || end > source.size())
                throw std::runtime_error("HttpGet source range out of bounds");
            const std::string newlines(std::count(source.begin() + begin, source.begin() + end, '\n'), '\n');
            if (group_lines && !newlines.empty())
                replacement = "(" + replacement + newlines + ")";
            else if (lines_before)
                replacement = newlines + replacement;
            else
                replacement += newlines;
            edits.push_back({ begin, end, std::move(replacement), edits.size() });
        }

        bool visit(Luau::AstExprIndexName* member) override
        {
            if (bindings.targets.contains(member) || !bindings.is_game(member->expr) || !member->index.value)
                return true;
            if (blocked_game_method(member->index.value))
            {
                edit(offset(member->location.begin), offset(member->location.end),
                    "tea.__blocked_game_member(\"" + std::string(member->index.value) + "\")", false, true);
                return true;
            }
            if (std::strcmp(member->index.value, "HttpGet") != 0 &&
                std::strcmp(member->index.value, "HttpGetAsync") != 0)
                return true;
            edit(offset(member->location.begin), offset(member->location.end), member->op == ':' ? "tea.httpget" : "tea.__httpget_unbound", false, true);
            return true;
        }

        bool visit(Luau::AstExprIndexExpr* member) override
        {
            if (bindings.targets.contains(member) || !bindings.is_game(member->expr)) return true;
            edit(offset(member->location.begin), offset(member->index->location.begin), "tea.__game_index(");
            edit(offset(member->index->location.end), offset(member->location.end), ")", true);
            return true;
        }
    } visitor(source, lines, bindings);
    parsed.root->visit(&visitor);

    std::sort(visitor.edits.begin(), visitor.edits.end(),
        [](const edit_t& a, const edit_t& b)
        {
            if (a.begin != b.begin) return a.begin > b.begin;
            if (a.end != b.end) return a.end > b.end;
            return a.order > b.order;
        });
    std::string rewritten = source;
    size_t boundary = source.size();
    for (const auto& edit : visitor.edits)
    {
        if (edit.end > boundary)
            throw std::runtime_error("HttpGet source edits overlap");
        rewritten.replace(edit.begin, edit.end - edit.begin, edit.replacement);
        boundary = edit.begin;
    }
    return rewritten;
}

class bytecode_encoder_t : public Luau::BytecodeEncoder {
    inline void encode(uint32_t* data, size_t count) override {
        for (auto i = 0u; i < count;) {
            auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
            i += Luau::getOpLength(LuauOpcode(opcode));
            opcode *= 227;
        }
    }
};

std::string compress(const std::string Bytecode) {
    size_t DataSize = Bytecode.size();
    size_t MaxSize = ZSTD_compressBound(DataSize);
    std::vector<char> Buffer(MaxSize + 8);

    memcpy(Buffer.data(), "RSB1", 4);
    memcpy(Buffer.data() + 4, &DataSize, sizeof(DataSize));

    size_t CompressedSize = ZSTD_compress(Buffer.data() + 8, MaxSize, Bytecode.data(), DataSize, ZSTD_maxCLevel());
    size_t TotalSize = CompressedSize + 8;

    uint32_t Key = XXH32(Buffer.data(), TotalSize, 42);
    uint8_t* KeyBytes = (uint8_t*)&Key;

    for (size_t i = 0; i < TotalSize; ++i) Buffer[i] ^= KeyBytes[i % 4] + i * 41;

    return std::string(Buffer.data(), TotalSize);
}

std::string _execution::compile_script(const std::string& source, bool resolve_http)
{
    static bytecode_encoder_t encoder = bytecode_encoder_t();

    static const char* CommonGlobals[] = { "Game", "Workspace", "game", "plugin", "script", "shared", "workspace", "_G", "_ENV", nullptr };
    Luau::CompileOptions Options;
    Options.debugLevel = 1;
    Options.optimizationLevel = 1;
    Options.mutableGlobals = CommonGlobals;
    Options.vectorLib = "Vector3";
    Options.vectorCtor = "new";
    Options.vectorType = "Vector3";
    Options.httpGetResolver = resolve_http ? "__tea_http_index" : nullptr;

    std::string rewritten;
    try
    {
        rewritten = game_httpget(source);
    }
    catch (const std::exception& error)
    {
        printf("[-] HttpGet rewrite failed: %s\n", error.what());
        return {};
    }
    const std::string bytecode = Luau::compile(rewritten, Options, {}, &encoder);

    if (bytecode.empty() || bytecode[0] == '\0') {
        printf("[-] compile error: %s\n", bytecode.empty() ? "(empty)" : bytecode.c_str() + 1);
        return {};
    }

    if (!signer->is_ready()) {
        printf("[!] signer not initialized, sending unsigned\n");
        return compress(bytecode);
    }

    auto signedData = signer->sign_bytecode(bytecode);
    if (signedData.empty()) {
        printf("[-] signing failed: %s\n", signer->last_error().c_str());
        return compress(bytecode);
    }

    std::string signedStr(signedData.begin(), signedData.end());
    return compress(signedStr);
}

void l_settop(uintptr_t state)
{
    auto top = memory->read<uintptr_t>(state + offsets::luau::lua_top);
    
    if (!top) return;

    memory->write<uintptr_t>(state + offsets::luau::lua_top, top - offsets::luau::tv_size);
}

uintptr_t l_gettop(uintptr_t state)
{
    return memory->read<uintptr_t>(state + offsets::luau::lua_top);
}

void _execution::set_thread_capabilities(uintptr_t state, uint64_t lvl, uint64_t caps)
{
    uintptr_t extra = memory->read<uintptr_t>(state + offsets::luau::l_userdata);
    if (!extra)
        return;

    memory->write<uint32_t>(extra + offsets::core::identity, static_cast<uint32_t>(lvl));
    memory->write<uint64_t>(extra + offsets::core::capabilities, caps);
}

void _execution::write_userdata(uintptr_t proto, uintptr_t caps)
{
    const uintptr_t field = proto + offsets::luau::p_userdata;
    memory->write<uint64_t>(field, caps + field);
}

uintptr_t _execution::read_userdata(uintptr_t proto)
{
    const uintptr_t field = proto + offsets::luau::p_userdata;
    return memory->read<uint64_t>(field) - field;
}

uintptr_t _execution::closure_from_top(uintptr_t state)
{
    const uintptr_t top = l_gettop(state);
    if (!top) return 0;

    const uintptr_t slot = top - offsets::luau::tv_size;

    const int tt = memory->read<int>(slot + offsets::luau::tv_tt);
    if (tt != offsets::luau::t_function) {
        printf("[-] top is tt=%d, expected %d (slot=0x%llX)\n", tt, offsets::luau::t_function, static_cast<unsigned long long>(slot));
        if (tt == 6) {
            const uintptr_t string_object = memory->read<uintptr_t>(slot + offsets::luau::tv_value);
            const uint32_t length = memory->read<uint32_t>(string_object + 0x14);
            if (string_object && length > 0 && length <= 512) {
                std::string message(length, '\0');
                if (injector->read_remote(string_object + 0x18, message.data(), length))
                    printf("[-] load message: %.*s\n", static_cast<int>(message.size()), message.c_str());
            }
        }
        return 0;
    }

    const uintptr_t closure = memory->read<uintptr_t>(slot + offsets::luau::tv_value);
    if (!closure) return 0;

    if (memory->read<uint8_t>(closure + offsets::luau::cl_isc) != 0) {
        printf("[-] closure is a C closure, no proto\n");
        return 0;
    }

    return memory->read<uintptr_t>(closure + offsets::luau::cl_proto);
}

void _execution::set_proto_caps(uintptr_t root, uintptr_t caps)
{
    if (!root) return;

    std::vector<uintptr_t> pending{ root };
    std::unordered_set<uintptr_t> seen;
    size_t budget = 100000;

    while (!pending.empty() && budget--) {
        const uintptr_t current = pending.back();
        pending.pop_back();

        if (!current || (current & 7) || !seen.insert(current).second)
            continue;

        const int sizep = memory->read<int>(current + offsets::luau::p_sizep);
        const uintptr_t nested = memory->read<uintptr_t>(current + offsets::luau::p_nested);

        if (sizep < 0 || sizep > 0x10000 || (sizep && !nested))
            continue;

        write_userdata(current, caps);

        for (int i = 0; i < sizep; ++i) {
            const uintptr_t child = memory->read<uintptr_t>(nested + i * 8);
            if (child) pending.push_back(child);
        }
    }
}

bool _execution::execute(const std::string& script, const std::string& chunkname, bool resolve_http)
{
    if (m_faulted.load() || !globals::lua_state) {
        return false;
    }

    uintptr_t fake_data_model = 0;
    uintptr_t data_model = 0;
    uint8_t loaded = 0;
    if (!memory->read_array(rebase(offsets::data_model::fake_data_model), std::span(&fake_data_model, 1)).ok(sizeof(fake_data_model)) ||
        !fake_data_model ||
        !memory->read_array(fake_data_model + offsets::data_model::real_data_model, std::span(&data_model, 1)).ok(sizeof(data_model)) ||
        data_model != globals::data_model ||
        !memory->read_array(data_model + offsets::data_model::game_loaded, std::span(&loaded, 1)).ok(sizeof(loaded)) ||
        loaded != 31)
        return false;

    const std::string bytecode = compile_script(script, resolve_http);
    if (bytecode.empty())
        return false;

    set_thread_capabilities(globals::lua_state, 8, offsets::luau::max_capabilities);

    const int status = functions->luavm_load(globals::lua_state, bytecode, chunkname.c_str(), 0);

    switch (status)
    {
    case LUA_OK:
    case LUA_YIELD:
        break;
    case LUA_ERRSYNTAX:
        printf("[-] script syntax error\n");
        return false;
    case LUA_ERRMEM:
        printf("[-] script memory allocation error\n");
        return false;
    case LUA_ERRRUN:
        printf("[-] script runtime error\n");
        return false;
    default:
        printf("[-] luavm_load failed (%d)\n", status);
        m_faulted.store(true);
        return false;
    }

    const uintptr_t proto = closure_from_top(globals::lua_state);
    if (!proto) {
        printf("[-] invalid vm stack\n");
        m_faulted.store(true);
        return false;
    }

    set_proto_caps(proto, globals::caps_remote);

    const uintptr_t back = read_userdata(proto);

    if (!functions->task_defer(globals::lua_state)) {
        printf("[-] task.defer failed\n");
        m_faulted.store(true);
        return false;
    }

    l_settop(globals::lua_state);
    return true;
}

uintptr_t _execution::initialize()
{
    uintptr_t identity = 0;
    uintptr_t script = 0;

    uintptr_t state = functions->get_global_state(globals::script_context, &identity, &script);
    if (!state) {
        printf("[-] did not find global state\n");
        return 0;
    }

    globals::lua_state = state;

    if (!globals::caps_remote) {
        globals::caps_remote = injector->alloc_remote(sizeof(uint64_t), PAGE_READWRITE);
        if (!globals::caps_remote) {
            return 0;
        }
        const uint64_t value = offsets::luau::max_capabilities;
        if (!injector->write_remote(globals::caps_remote, &value, sizeof(value))) {
            return 0;
        }
    }

    return state;
}
