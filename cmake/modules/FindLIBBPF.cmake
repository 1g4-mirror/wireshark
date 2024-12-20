# Find libbpf library
find_library(LIBBPF_LIBRARY NAMES bpf HINTS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu)
# Find libbpf headers (bpf.h)
find_path(LIBBPF_INCLUDE_DIR NAMES bpf/bpf.h HINTS /usr/include /usr/local/include)

# Set the result variables
if (LIBBPF_LIBRARY AND LIBBPF_INCLUDE_DIR)
    set(LIBBPF_FOUND TRUE)
    set(LIBBPF_LIBRARIES ${LIBBPF_LIBRARY})
    set(LIBBPF_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIR})
else()
    set(LIBBPF_FOUND FALSE)
endif()

# Mark the variables as advanced to hide them from the GUI
mark_as_advanced(LIBBPF_LIBRARY LIBBPF_INCLUDE_DIR)