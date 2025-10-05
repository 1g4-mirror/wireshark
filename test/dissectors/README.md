## Dissector unit tests

This is an experimental unit test framework for dissectors that allows
dissecting a buffer with a specific dissector and checking that the resulting
tree has the expected values. The tests are built as part of the test-programs
target into the `run/dissectors_test` binary and can be run manually using the
binary or automatically by pytest and the CI suite.

To produce stack traces when tests fail pytest runs `dissectors_test` though
GDB. To reproduce this yourself outside pytest you can run `gdb -x
test/dissectors/test_runner.gdb build/run/dissectors_test` (see
`test/suite_unittests.py` for the full command). If you want to run a subset of
test cases the `-r` option can be use with a test name (`-r /ip/packet`) for
one test, or a prefix (`-r /ip`) to run all tests in a group.


### Asserts

The Glib testing framework is available and provides `g_assert_true()` and a few
other asserts for comparing basic data types that can be found in the [Glib
documentation](https://docs.gtk.org/glib/func.assert_true.html?q=g_assert).
There are also a handful of Wireshark specific tests in `assert.h` to help with
checking various details of the protocol tree, and this could be a good location to
put new asserts you write that might be useful for other protocols. Finally,
making protocol specific asserts in the test file can be a nice way to make each
test more readable.

Note that `g_assert()` can be disabled and should not be used in unit tests, use
`g_assert_true()` instead.


### Navigating the protocol tree

The most convenient, readable and future proof way to find the right
`proto_node` will likely be using the display filter name
(`header_field_info->abbrev`) with `find_child` or other functions that use the
name to find nodes. Using the name avoids writing tests that will fail in the
future when other unrelated items are added to the protocol tree and makes it
easier to understand the intent.


### Testing heuristic dissectors

Testing a heuristic dissector is very similar to testing a regular dissector,
but needs a few changes. To look up the dissector use the internal name with
`find_heur_dissector_by_unique_short_name` to get a `heur_dtbl_entry_t`, and
call the function pointer in the `dissector` member:

```
heur_dtbl_entry_t * dissector_info = find_heur_dissector_by_unique_short_name(
        "bittorrent_dht_udp");
const gboolean result = dissector_info->dissector(
            buffer,
            tree->tree_data->pinfo,
            tree,
            NULL);
```


## Testing a new protocol

To add the first test for a protocol add two new files for your protocol.
`test_packet-<protocol>.h` declares a function `void add_<protocol>_tests(void);`
that is called from `test_dissectors.c`. The definition of the function goes in
`test_packet-<protocol>.c` and holds all the calls to `test_case_add` (or its
glib equivalents) for each of the test cases in that file. The C file must be
added to `DISSECTOR_TEST_SRC` in `test/dissectors/CMakeLists.txt`.

To call the dissector with your buffer use the epan find and call functions.
Combined with `to_buffer` to convert a C buffer to a tvbuff the shared code can
look like this:
```
static int
dissect_packet(proto_tree * tree, const char * data, const size_t length)
{
    const dissector_handle_t handle = find_dissector("<protocol>");
    tvbuff_t * buffer = to_buffer(data, length);
    const int result = call_dissector_only(
            handle,
            buffer,
            tree->tree_data->pinfo,
            tree,
            NULL);
    tvb_free(buffer);
    return result;
}
```

The skeleton for each test then looks like this:
```
static void
test_packet(void)
{
    proto_tree * tree = make_tree();
    const char data[] = "\x12\x34\x56";
    dissect_packet(tree, data, sizeof(data));
    clean_tree(tree);
}
```
