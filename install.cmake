if(UNIX)
    SET(CMAKE_INSTALL_PREFIX /usr)
    install(TARGETS smithproxy DESTINATION bin)
    install(TARGETS smithd DESTINATION bin)
    install(FILES man/smithproxy.1 DESTINATION share/man/man1)
    install_if_not_exists(etc/smithproxy.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.key /etc/smithproxy)
    install_if_not_exists(etc/smithproxy.startup.cfg /etc/smithproxy)
    install_if_not_exists(etc/smithd.cfg /etc/smithproxy)

    install(DIRECTORY DESTINATION /etc/smithproxy/certs/)
    install(DIRECTORY DESTINATION /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/ca-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/ca-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/srv-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/srv-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/cl-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/cl-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/portal-gen.info /etc/smithproxy/certs/default)


    install(FILES etc/smithproxy.startup.sh DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_network
            )
    install(FILES etc/smithproxy.init DESTINATION /etc/init.d RENAME smithproxy
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            )
    install(FILES etc/smithproxy_cli.sh DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_cli
            )

    install(FILES tools/sx_certinfo_ca DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            )

    install(FILES tools/sx_download_ctlog DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            )


    install(FILES man/TESTING_README.txt DESTINATION share/smithproxy/docs)

    # install infra/
    file(GLOB infra_py "src/infra/*.py" EXCLUDE "src/infra/smithdog.py")
    install(FILES ${infra_py} DESTINATION share/smithproxy/infra)

    file(GLOB infra_exe_py "src/infra/smithdog.py")
    install(FILES ${infra_exe_py} DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_ctl
            )

    install(DIRECTORY src/infra/sslca DESTINATION share/smithproxy/infra)

    file(GLOB sslca_makecerts "src/infra/sslca/make*.py")
    install(FILES ${sslca_makecerts} DESTINATION share/smithproxy/infra/sslca
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            )



    install(FILES src/infra/sslca/makecerts.py DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_regencerts
            )


    # portal installation
    install(FILES src/infra/sslca/makeportalcert.py DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_autoportalcert
            )




    install(DIRECTORY etc/msg DESTINATION /etc/smithproxy)

    # message: edit defaults and add to init.d to start at boot!
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")
    install(CODE "MESSAGE(\" | Core installation complete!                                                            |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------|\")")
    install(CODE "MESSAGE(\" |   Hints for minimal setup:                                                             |\")")
    install(CODE "MESSAGE(\" |     1:Edit /etc/smithproxy/smithproxy.startup.cfg                                      |\")")
    install(CODE "MESSAGE(\" |       -  change interface heading to the LAN/internal network you want to inspect.     |\")")
    install(CODE "MESSAGE(\" |     2:Make smithproxy start on boot                                                    |\")")
    install(CODE "MESSAGE(\" |       -  Debian:  update-rc.d smithproxy defaults                                      |\")")
    install(CODE "MESSAGE(\" |     3:Enable smithproxy CLI                                                            |\")")
    install(CODE "MESSAGE(\" |       -  add /usr/bin/smithproxy_cli to /etc/shells, make special user for it, use ssh |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")

endif()
