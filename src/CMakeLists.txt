add_executable(dumppcap2udp main.c udp.c log.c)

include_directories(${PCAP_LIBRARIES})
target_link_libraries(schlossoeffner ${LIBS} ${PCAP_LIBRARIES})

install(TARGETS schlossoeffner
    RUNTIME DESTINATION bin
    )

