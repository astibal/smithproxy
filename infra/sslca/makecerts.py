import sxyca

if __name__ == "__main__":
    sxyca._write_default_settings()
    sxyca.load_settings()

    # generate CA RSA key
    ca_key = generate_rsa_key(2048)
    save_key(ca_key, "ca-key.pem", None)

    # generate CA CSR for self-signing & self-sign
    ca_csr = sxyca.generate_csr(ca_key, "ca", isca=True)
    ca_cert = sxyca.sign_csr(ca_key, ca_csr, "ca", valid=3 * 30, isca=True)
    sxyca.save_certificate(ca_cert, "ca-cert.pem")

    # generate default server key and certificate & sign by CA
    srv_key = sxyca.generate_rsa_key(2048)
    srv_csr = sxyca.generate_csr(srv_key, "srv", sans_dns=["portal.demo.smithproxy.net", ])
    srv_cert = sxyca.sign_csr(ca_key, srv_csr, "ca", valid=30, cacert=ca_cert,
                        aia_issuers=["http://192.168.122.1:8444/ca-cert.pem",],
                        ocsp_responders=["http://192.168.122.1:8888/ocsp",])
    sxyca.save_certificate(srv_cert, "srv-cert.pem")

    # Experimental: generate EC CA key
    ec_ca_key = sxyca.generate_ec_key(ec.SECP256K1())
    sxyca.save_key(ec_ca_key, "ec-ca-key.pem", None)

    # self-sign
    ec_ca_csr = sxyca.generate_csr(ec_ca_key, "ca", isca=True)
    ec_ca_cert = sxyca.sign_csr(ec_ca_key, ec_ca_csr, "ca", valid=6 * 30, isca=True)
    sxyca.save_certificate(ec_ca_cert, "ec-ca-cert.pem")