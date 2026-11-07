#include "instances.h"

uintptr_t _instances::get_data_model()
{
    uintptr_t fake_data_model = memory->read<uintptr_t>(rebase(offsets::data_model::fake_data_model));

	if (!fake_data_model) return 0;

	uintptr_t data_model = memory->read<uintptr_t>(fake_data_model + offsets::data_model::real_data_model);

	if (!data_model) return 0;

	globals::data_model = data_model;

	return globals::data_model;
}

uintptr_t _instances::get_script_context()
{
    uintptr_t children_start = memory->read<uintptr_t>(globals::data_model + offsets::data_model::children);

    if (!children_start) return 0;

    uintptr_t first_child = memory->read<uintptr_t>(children_start);

    if (!first_child) return 0;

    uintptr_t script_context = memory->read<uintptr_t>(first_child + offsets::data_model::script_context);

    if (!script_context) return 0;

    globals::script_context = script_context;

    return globals::script_context;
}

std::string _instances::read_string(uint64_t string)
{
    const auto length = memory->read<int>(string + offsets::string::string_length);

    if (length >= 16u)
    {
        string = memory->read<uint64_t>(string);
    }

    std::string result;
    char character = 0;
    int char_size = sizeof(character);
    int offset = 0;

    result.reserve(204);

    while (offset < 200)
    {
        character = memory->read<char>(string + offset);

        if (character == 0)
            break;

        offset += char_size;
        result.push_back(character);
    }

    return result;
}

std::string _instances::get_name(uintptr_t instance)
{
    if (!instance) return {};

    const uintptr_t name_ptr = memory->read<uintptr_t>(instance + offsets::instance::name);
    if (!name_ptr) return {};

    return read_string(name_ptr);
}
