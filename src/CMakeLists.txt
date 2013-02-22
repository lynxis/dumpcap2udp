add_executable(dumpcap2udp main.c udp.c log.c)

include_directories(${PCAP_INCLUDE_DIRS})
target_link_libraries(dumpcap2udp ${LIBS} ${PCAP_LIBRARIES})

install(TARGETS dumpcap2udp
    RUNTIME DESTINATION bin
    )

