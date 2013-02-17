ADD_EXECUTABLE(dumppcap2udp main.c udp.c log.c)

TARGET_LINK_LIBRARIES(schlossoeffner ${LIBS})

INSTALL(TARGETS schlossoeffner
    RUNTIME DESTINATION bin
    )

