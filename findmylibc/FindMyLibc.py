import requests
import itertools

_json_headers = {'Content-Type': 'application/json'}

_common_symbols_to_leak = ['__libc_start_main', 'puts', 'printf', 'gets', 'read', 'write', 'send', 'recv']

"""
Returns: smallest list of matching libs (each lib is dict with 'id' 'download_url', 'base_address', 'syms' and more)
The 'syms' is a dictionary of {symbol_name_str: calculated_address_integer} 
"""
def find_libc(elf, leak_symbol_address, stop_libs_amount=3):
    matching_libc = _get_libc_versions(elf, leak_symbol_address, stop_libs_amount)
    for lib in matching_libc:
        all_symbols_raw_response = requests.get(lib['symbols_url'], headers=_json_headers)
        symbol_name_to_offset = {i.split(' ')[0]: i.split(' ')[-1] for i in all_symbols_raw_response.content.decode("utf-8").strip().split('\n')}

        for name, string_value in symbol_name_to_offset.items():
            symbol_name_to_offset[name] = _string_to_hex(string_value) + lib['base_address']

        lib['syms'] = symbol_name_to_offset

    return matching_libc


"""
Returns: returns same as `find_libc` but without the `syms` dict
"""
def _get_libc_versions(elf, leak_symbol_address, stop_libs_amount=3):
    url = 'https://libc.rip/api/find'
    got_symbols = [symbol for symbol in _common_symbols_to_leak if symbol in elf.got]
    leaked_symbols_for_request = {"symbols": {}}
    leaked_addresses_cache = {}
    least_matching_libs = []

    print(f"Searching matching libc versions from {url}")

    for addresses_count in range(1, len(got_symbols) + 1):
        for symbol_combination in itertools.combinations(got_symbols, addresses_count):
            for symbol in symbol_combination:
                if symbol in leaked_addresses_cache:
                    leaked_symbols_for_request["symbols"][symbol] = leaked_addresses_cache[symbol]
                else:
                    leaked_address = leak_symbol_address(symbol)
                    if leaked_address:
                        ensure_leaked_address_type(leaked_address)
                        leaked_symbols_for_request["symbols"][symbol] = hex(leaked_address)
                        leaked_addresses_cache[symbol] = hex(leaked_address)

            if not leaked_symbols_for_request["symbols"]:
                continue

            response = requests.post(url, headers=_json_headers, json=leaked_symbols_for_request)
            matching_libs = response.json()

            if not matching_libs:
                continue

            matching_libs = _add_base_address(matching_libs, leaked_symbols_for_request)

            if _is_fewer_matching_libs(least_matching_libs, matching_libs):
                least_matching_libs = matching_libs

            if len(least_matching_libs) <= stop_libs_amount:
                print(f"Found {len(least_matching_libs)} matching libc versions. Stopping search due to set limit of {stop_libs_amount}")
                _print_matching_libs(least_matching_libs)

                return least_matching_libs

            if len(matching_libs) == 1:
                print(f"Found unique libc version! :\n{matching_libs['id']}")

                return matching_libs

            leaked_symbols_for_request["symbols"] = {}

    _print_matching_libs(least_matching_libs)

    return least_matching_libs


def ensure_leaked_address_type(leaked_address):
    if type(leaked_address) is not int:
        raise Exception("\n[FindMyLibc]:\nYour function 'leak_symbol_address' "
               "should return integer value of an address,"
               f" instead got value of type {type(leaked_address)}")


def _add_base_address(matching_libs_response, leaked_symbols_for_request):
    for lib in matching_libs_response:
        lib['base_address'] = next((_string_to_hex(leaked_symbols_for_request['symbols'][name]) - _string_to_hex(offset))
                                   for (name,offset) in lib['symbols'].items()
                                   if name in leaked_symbols_for_request['symbols'].keys())

    return matching_libs_response


def _string_to_hex(hex_as_string):
    return int(hex_as_string, 16)


def _is_fewer_matching_libs(current_least_matching_libs, matching_libs):
    return not current_least_matching_libs or (matching_libs and len(matching_libs) < len(current_least_matching_libs))


def _print_matching_libs(matching_libs):
    if not matching_libs:
        raise Exception("\n[FindMyLibc]:\nNo matching libc versions were found :(\nMake sure that your leaking function works properly.")

    matching_libs_output = '\n'.join([lib['id'] for lib in matching_libs])
    print(f"Matching libc versions:\n{matching_libs_output}")


__all__ = ["find_libc"]