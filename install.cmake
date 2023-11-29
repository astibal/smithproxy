if(UNIX)
    SET(CMAKE_INSTALL_PREFIX /usr)
    install(TARGETS smithproxy DESTINATION bin)
    install(FILES man/smithproxy.1 DESTINATION share/man/man1)
    install_if_not_exists(etc/smithproxy.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.cfg /etc/smithproxy)
    install_if_not_exists(etc/users.key /etc/smithproxy)
    install_if_not_exists(etc/smithproxy.startup.cfg /etc/smithproxy)
    install_if_not_exists(etc/apparmor/usr.bin.smithproxy /etc/apparmor.d/)

    install(DIRECTORY DESTINATION /etc/smithproxy/certs/)
    install(DIRECTORY DESTINATION /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/ca-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/ca-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/srv-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/srv-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/cl-cert.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/cl-key.pem /etc/smithproxy/certs/default)
    install_if_not_exists(etc/certs/default/portal-gen.info /etc/smithproxy/certs/default)

    install_if_not_exists(etc/logrotate.d/smithproxy /etc/logrotate.d)

    install(FILES etc/smithproxy.startup.sh DESTINATION bin
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            RENAME sx_network
            )
    install(FILES etc/service/initd/smithproxy.init DESTINATION share/smithproxy/service
            PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            )

    install(FILES etc/service/systemd/sx-core@.service DESTINATION /usr/lib/systemd/system
            PERMISSIONS
            OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(FILES etc/service/systemd/sx-network@.service DESTINATION /usr/lib/systemd/system
            PERMISSIONS
            OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)


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

    install(FILES tools/sx_download_ca_bundle DESTINATION bin
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

    create_dir("/var/log/smithproxy/")
    create_dir("/var/smithproxy/data/")

    # message: edit defaults and add to init.d to start at boot!
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")
    install(CODE "MESSAGE(\" | Installation complete!                                                                 |\")")
    install(CODE "MESSAGE(\" +----------------------------------------------------------------------------------------+\")")

endif()
