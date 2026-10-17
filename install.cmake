include(GNUInstallDirs)

# Both debhelper and CPack consume this manifest. Keep package-specific
# lifecycle policy in debian/, not in CMake install-time code.
if(UNIX)
    install(TARGETS smithproxy
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT runtime)

    install(FILES man/smithproxy.1
            DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
            COMPONENT runtime)

    set(SMITHPROXY_SYSCONFDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/smithproxy")

    foreach(config_file
            etc/smithproxy.cfg
            etc/users.cfg
            etc/users.key
            etc/smithproxy.startup.cfg)
        install_if_not_exists("${config_file}" "${SMITHPROXY_SYSCONFDIR}")
    endforeach()

    install_if_not_exists(etc/apparmor/usr.bin.smithproxy
                          "${CMAKE_INSTALL_FULL_SYSCONFDIR}/apparmor.d")

    install(DIRECTORY etc/certs/default/
            DESTINATION "${SMITHPROXY_SYSCONFDIR}/certs/default"
            COMPONENT runtime
            FILES_MATCHING
            PATTERN "*-cert.pem"
            PATTERN "portal-gen.info"
            PATTERN "sslca.json")

    install(DIRECTORY etc/certs/default/
            DESTINATION "${SMITHPROXY_SYSCONFDIR}/certs/default"
            COMPONENT runtime
            FILE_PERMISSIONS OWNER_READ OWNER_WRITE
            FILES_MATCHING PATTERN "*-key.pem")

    install(CODE "
        file(CHMOD
             \"\$ENV{DESTDIR}${SMITHPROXY_SYSCONFDIR}/users.key\"
             PERMISSIONS OWNER_READ OWNER_WRITE)
    ")

    install(FILES etc/logrotate.d/smithproxy
            DESTINATION "${CMAKE_INSTALL_FULL_SYSCONFDIR}/logrotate.d"
            COMPONENT runtime)

    install(PROGRAMS etc/smithproxy.startup.sh
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            RENAME sx_network
            COMPONENT runtime)

    install(PROGRAMS etc/smithproxy_cli.sh
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            RENAME sx_cli
            COMPONENT runtime)

    install(PROGRAMS
            tools/sx_certinfo_ca
            tools/sx_certinfo_portal
            tools/sx_download_ctlog
            tools/sx_download_ca_bundle
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT runtime)

    # This path is intentionally not CMAKE_INSTALL_LIBDIR: systemd units are
    # architecture-independent and belong in /usr/lib/systemd/system.
    install(FILES
            etc/service/systemd/sx-core@.service
            etc/service/systemd/sx-network@.service
            DESTINATION "lib/systemd/system"
            COMPONENT runtime)

    install(FILES man/TESTING_README.txt
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/docs"
            COMPONENT runtime)

    install(FILES
            src/ext/ls-qpack/LICENSE.ls-qpack
            src/ext/ls-qpack/LICENSE.xxhash
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/docs/licenses"
            COMPONENT runtime)

    install(FILES
            tools/wireshark/spquic.lua
            tools/wireshark/README.md
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/wireshark"
            COMPONENT runtime)

    file(GLOB infra_py CONFIGURE_DEPENDS "src/infra/*.py")
    install(FILES ${infra_py}
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/infra"
            COMPONENT runtime)

    install(DIRECTORY src/infra/sslca
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/infra"
            COMPONENT runtime
            PATTERN "__pycache__" EXCLUDE
            PATTERN "*.pyc" EXCLUDE)

    file(GLOB sslca_makecerts CONFIGURE_DEPENDS "src/infra/sslca/make*.py")
    install(PROGRAMS ${sslca_makecerts}
            DESTINATION "${CMAKE_INSTALL_DATADIR}/smithproxy/infra/sslca"
            COMPONENT runtime)

    install(PROGRAMS src/infra/sslca/makecerts.py
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            RENAME sx_regencerts
            COMPONENT runtime)

    install(PROGRAMS src/infra/sslca/makeportalcert.py
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            RENAME sx_autoportalcert
            COMPONENT runtime)

    install(DIRECTORY etc/msg
            DESTINATION "${SMITHPROXY_SYSCONFDIR}"
            COMPONENT runtime)
endif()
