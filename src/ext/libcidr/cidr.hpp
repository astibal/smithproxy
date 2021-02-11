/*
 * libcidr.h - Header file for libCIDR
 */

#ifndef __LIBCIDR_H
#define __LIBCIDR_H

#ifdef __cplusplus
extern "C"{
#endif 

/* We need the fixed-size int types.  See discussion below. */
#include <cinttypes>

/* We need the struct in[6]_addr defs */
#include <netinet/in.h>


namespace cidr {
/* CONSTANTS */
/* String forms (cidr_to_str()) */
#define CIDR_NOFLAGS      (0)
#define CIDR_NOCOMPACT    (1) /* Don't do :: compaction */
#define CIDR_VERBOSE      (1<<1) /* Don't minimize leading zeros */
#define CIDR_USEV6        (1<<2) /* Use v6 form for v4 addresses */
#define CIDR_USEV4COMPAT  (1<<3) /* Use v4-compat rather than v4-mapped */
#define CIDR_NETMASK      (1<<4) /* Show netmask instead of pflen */
#define CIDR_ONLYADDR     (1<<5) /* Only show the address */
#define CIDR_ONLYPFLEN    (1<<6) /* Only show the pf/mask */
#define CIDR_WILDCARD     (1<<7) /* Show wildcard-mask instead of netmask */
#define CIDR_FORCEV6      (1<<8) /* Force treating as v6 address */
#define CIDR_FORCEV4      (1<<9) /* Force treating as v4 address */
#define CIDR_REVERSE      (1<<10) /* Return a DNS PTR name */

/* Protocols */
#define CIDR_NOPROTO        0
#define CIDR_IPV4           1
#define CIDR_IPV6           2

/* Versioning info */
#define CIDR_VERSION "1.2.4"
#define CIDR_RELEASE "release"
#define CIDR_REVISION " (custom smithproxy fork)"
#define CIDR_VERSION_STR (CIDR_VERSION "-" CIDR_RELEASE CIDR_REVISION)


/* DATA STRUCTURES */
/*
 * Discussion:
 * uint*_t are defined by POSIX and C99.  We only probably NEED stdint.h
 * defines, since we don't need the various output stuff.  However, for
 * now, we'll get all of inttypes.h because some older platforms only
 * have it, and define the uint*_t's in there (FreeBSD 4.x being the most
 * obvious one I care about).  Revisit this down the line if necessary.
 *
 * Note that you should almost certainly not be messing with this
 * structure directly from external programs.  Use the cidr_get_*()
 * functions to get a copy to work with.
 */
    struct cidr_addr {
        int version;
        uint8_t addr[16];
        uint8_t mask[16];
        int proto;
    };
    typedef struct cidr_addr CIDR;



    [[nodiscard]] CIDR *cidr_addr_broadcast (const CIDR *);

    [[nodiscard]] CIDR *cidr_addr_hostmax (const CIDR *);

    [[nodiscard]] CIDR *cidr_addr_hostmin (const CIDR *);

    [[nodiscard]] CIDR *cidr_addr_network (const CIDR *);

    [[nodiscard]] CIDR *cidr_alloc ();

    int cidr_contains (const CIDR *, const CIDR *);

    [[nodiscard]] CIDR *cidr_dup (const CIDR *);

    int cidr_equals (const CIDR *, const CIDR *);

    void cidr_free (CIDR *);

    [[nodiscard]] CIDR *cidr_from_inaddr (const struct in_addr *);

    [[nodiscard]] CIDR *cidr_from_in6addr (const struct in6_addr *);

    [[nodiscard]] CIDR *cidr_from_str (const char *);

    [[nodiscard]] uint8_t *cidr_get_addr (const CIDR *);

    [[nodiscard]] uint8_t *cidr_get_mask (const CIDR *);

    int cidr_get_pflen (const CIDR *);

    int cidr_get_proto (const CIDR *);

    int cidr_is_v4mapped (const CIDR *);

    [[nodiscard]] CIDR **cidr_net_subnets (const CIDR *);

    [[nodiscard]] CIDR *cidr_net_supernet (const CIDR *);

    const char *cidr_numaddr (const CIDR *);

    const char *cidr_numaddr_pflen (int);

    const char *cidr_numhost (const CIDR *);

    const char *cidr_numhost_pflen (int);

    [[nodiscard]] struct in_addr *cidr_to_inaddr (const CIDR *, struct in_addr *);

    [[nodiscard]] struct in6_addr *cidr_to_in6addr (const CIDR *, struct in6_addr *);

    [[nodiscard]] char *cidr_to_str (const CIDR *c, int flags = CIDR_NOFLAGS);

    const char *cidr_version (void);
}

#ifdef __cplusplus
}
#endif 
        
#endif /* __LIBCIDR_H */
