add_executable(dumppcap2udp main.c udp.c log.c)

include_directories(${PCAP_LIBRARIES})
target_link_libraries(dumppcap2udp ${LIBS} ${PCAP_LIBRARIES})

install(TARGETS dumppcap2udp
    RUNTIME DESTINATION bin
    )

