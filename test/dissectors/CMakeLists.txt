set(DISSECTOR_TEST_SRC
	assert.c
	test_dissectors.c
	test_packet-bt-dht.c
	test_packet-ip.c
	test_packet-tcp.c
	test_packet-udp.c
	test_unittest_utils.c
	unittest_utils.c
)

add_library(dissector-test-objs OBJECT
	${DISSECTOR_TEST_SRC}
)

set_source_files_properties(
	${DISSECTOR_TEST_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_executable(dissectors_test EXCLUDE_FROM_ALL
	$<TARGET_OBJECTS:crypt>
	$<TARGET_OBJECTS:dfilter>
	$<TARGET_OBJECTS:dissector-registration>
	$<TARGET_OBJECTS:dissector-test-objs>
	$<TARGET_OBJECTS:dissectors-corba>
	$<TARGET_OBJECTS:dissectors>
	$<TARGET_OBJECTS:epan_objects>
	$<TARGET_OBJECTS:ftypes>
	$<$<BOOL:${LUA_FOUND}>:$<TARGET_OBJECTS:wslua>>
)

target_link_libraries(dissectors_test
	wiretap
	${BROTLI_LIBRARIES}
	${CARES_LIBRARIES}
	${GCRYPT_LIBRARIES}
	${GLIB2_LIBRARIES}
	${GNUTLS_LIBRARIES}
	${KERBEROS_LIBRARIES}
	${LIBXML2_LIBRARIES}
	${LUA_LIBRARIES}
	${LZ4_LIBRARIES}
	${M_LIBRARIES}
	${NGHTTP2_LIBRARIES}
	${NGHTTP3_LIBRARIES}
	${SMI_LIBRARIES}
	${SNAPPY_LIBRARIES}
	${ZLIB_LIBRARIES}
	${ZSTD_LIBRARIES}
	$<$<BOOL:${LUA_FOUND}>:lrexlib>
)
