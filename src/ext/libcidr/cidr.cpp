/*
 * Functions to generate various addresses based on a CIDR
 */

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cctype>

#include <strings.h>
#include <arpa/inet.h>

#include <ext/libcidr/cidr.hpp>

namespace cidr {

/* Powers of two */

    static const char** cidr_pow2() {
        static const char *pow2[] = {
                "1",
                "2",
                "4",
                "8",
                "16",
                "32",
                "64",
                "128",
                "256",
                "512",
                "1,024",
                "2,048",
                "4,096",
                "8,192",
                "16,384",
                "32,768",
                "65,536",
                "131,072",
                "262,144",
                "524,288",
                "1,048,576",
                "2,097,152",
                "4,194,304",
                "8,388,608",
                "16,777,216",
                "33,554,432",
                "67,108,864",
                "134,217,728",
                "268,435,456",
                "536,870,912",
                "1,073,741,824",
                "2,147,483,648",
                "4,294,967,296",
                "8,589,934,592",
                "17,179,869,184",
                "34,359,738,368",
                "68,719,476,736",
                "137,438,953,472",
                "274,877,906,944",
                "549,755,813,888",
                "1,099,511,627,776",
                "2,199,023,255,552",
                "4,398,046,511,104",
                "8,796,093,022,208",
                "17,592,186,044,416",
                "35,184,372,088,832",
                "70,368,744,177,664",
                "140,737,488,355,328",
                "281,474,976,710,656",
                "562,949,953,421,312",
                "1,125,899,906,842,624",
                "2,251,799,813,685,248",
                "4,503,599,627,370,496",
                "9,007,199,254,740,992",
                "18,014,398,509,481,984",
                "36,028,797,018,963,968",
                "72,057,594,037,927,936",
                "144,115,188,075,855,872",
                "288,230,376,151,711,744",
                "576,460,752,303,423,488",
                "1,152,921,504,606,846,976",
                "2,305,843,009,213,693,952",
                "4,611,686,018,427,387,904",
                "9,223,372,036,854,775,808",
                "18,446,744,073,709,551,616",
                "36,893,488,147,419,103,232",
                "73,786,976,294,838,206,464",
                "147,573,952,589,676,412,928",
                "295,147,905,179,352,825,856",
                "590,295,810,358,705,651,712",
                "1,180,591,620,717,411,303,424",
                "2,361,183,241,434,822,606,848",
                "4,722,366,482,869,645,213,696",
                "9,444,732,965,739,290,427,392",
                "18,889,465,931,478,580,854,784",
                "37,778,931,862,957,161,709,568",
                "75,557,863,725,914,323,419,136",
                "151,115,727,451,828,646,838,272",
                "302,231,454,903,657,293,676,544",
                "604,462,909,807,314,587,353,088",
                "1,208,925,819,614,629,174,706,176",
                "2,417,851,639,229,258,349,412,352",
                "4,835,703,278,458,516,698,824,704",
                "9,671,406,556,917,033,397,649,408",
                "19,342,813,113,834,066,795,298,816",
                "38,685,626,227,668,133,590,597,632",
                "77,371,252,455,336,267,181,195,264",
                "154,742,504,910,672,534,362,390,528",
                "309,485,009,821,345,068,724,781,056",
                "618,970,019,642,690,137,449,562,112",
                "1,237,940,039,285,380,274,899,124,224",
                "2,475,880,078,570,760,549,798,248,448",
                "4,951,760,157,141,521,099,596,496,896",
                "9,903,520,314,283,042,199,192,993,792",
                "19,807,040,628,566,084,398,385,987,584",
                "39,614,081,257,132,168,796,771,975,168",
                "79,228,162,514,264,337,593,543,950,336",
                "158,456,325,028,528,675,187,087,900,672",
                "316,912,650,057,057,350,374,175,801,344",
                "633,825,300,114,114,700,748,351,602,688",
                "1,267,650,600,228,229,401,496,703,205,376",
                "2,535,301,200,456,458,802,993,406,410,752",
                "5,070,602,400,912,917,605,986,812,821,504",
                "10,141,204,801,825,835,211,973,625,643,008",
                "20,282,409,603,651,670,423,947,251,286,016",
                "40,564,819,207,303,340,847,894,502,572,032",
                "81,129,638,414,606,681,695,789,005,144,064",
                "162,259,276,829,213,363,391,578,010,288,128",
                "324,518,553,658,426,726,783,156,020,576,256",
                "649,037,107,316,853,453,566,312,041,152,512",
                "1,298,074,214,633,706,907,132,624,082,305,024",
                "2,596,148,429,267,413,814,265,248,164,610,048",
                "5,192,296,858,534,827,628,530,496,329,220,096",
                "10,384,593,717,069,655,257,060,992,658,440,192",
                "20,769,187,434,139,310,514,121,985,316,880,384",
                "41,538,374,868,278,621,028,243,970,633,760,768",
                "83,076,749,736,557,242,056,487,941,267,521,536",
                "166,153,499,473,114,484,112,975,882,535,043,072",
                "332,306,998,946,228,968,225,951,765,070,086,144",
                "664,613,997,892,457,936,451,903,530,140,172,288",
                "1,329,227,995,784,915,872,903,807,060,280,344,576",
                "2,658,455,991,569,831,745,807,614,120,560,689,152",
                "5,316,911,983,139,663,491,615,228,241,121,378,304",
                "10,633,823,966,279,326,983,230,456,482,242,756,608",
                "21,267,647,932,558,653,966,460,912,964,485,513,216",
                "42,535,295,865,117,307,932,921,825,928,971,026,432",
                "85,070,591,730,234,615,865,843,651,857,942,052,864",
                "170,141,183,460,469,231,731,687,303,715,884,105,728",
                "340,282,366,920,938,463,463,374,607,431,768,211,456"};

        return pow2;
    }

    /* Powers of 2 minus two; hosts in a subnet with this many host bit */

    static const char** cidr_pow2m2() {
        static const char *pow2m2[] = {
                "1", /* Special */
                "2", /* Special */
                "2",
                "6",
                "14",
                "30",
                "62",
                "126",
                "254",
                "510",
                "1,022",
                "2,046",
                "4,094",
                "8,190",
                "16,382",
                "32,766",
                "65,534",
                "131,070",
                "262,142",
                "524,286",
                "1,048,574",
                "2,097,150",
                "4,194,302",
                "8,388,606",
                "16,777,214",
                "33,554,430",
                "67,108,862",
                "134,217,726",
                "268,435,454",
                "536,870,910",
                "1,073,741,822",
                "2,147,483,646",
                "4,294,967,294",
                "8,589,934,590",
                "17,179,869,182",
                "34,359,738,366",
                "68,719,476,734",
                "137,438,953,470",
                "274,877,906,942",
                "549,755,813,886",
                "1,099,511,627,774",
                "2,199,023,255,550",
                "4,398,046,511,102",
                "8,796,093,022,206",
                "17,592,186,044,414",
                "35,184,372,088,830",
                "70,368,744,177,662",
                "140,737,488,355,326",
                "281,474,976,710,654",
                "562,949,953,421,310",
                "1,125,899,906,842,622",
                "2,251,799,813,685,246",
                "4,503,599,627,370,494",
                "9,007,199,254,740,990",
                "18,014,398,509,481,982",
                "36,028,797,018,963,966",
                "72,057,594,037,927,934",
                "144,115,188,075,855,870",
                "288,230,376,151,711,742",
                "576,460,752,303,423,486",
                "1,152,921,504,606,846,974",
                "2,305,843,009,213,693,950",
                "4,611,686,018,427,387,902",
                "9,223,372,036,854,775,806",
                "18,446,744,073,709,551,614",
                "36,893,488,147,419,103,230",
                "73,786,976,294,838,206,462",
                "147,573,952,589,676,412,926",
                "295,147,905,179,352,825,854",
                "590,295,810,358,705,651,710",
                "1,180,591,620,717,411,303,422",
                "2,361,183,241,434,822,606,846",
                "4,722,366,482,869,645,213,694",
                "9,444,732,965,739,290,427,390",
                "18,889,465,931,478,580,854,782",
                "37,778,931,862,957,161,709,566",
                "75,557,863,725,914,323,419,134",
                "151,115,727,451,828,646,838,270",
                "302,231,454,903,657,293,676,542",
                "604,462,909,807,314,587,353,086",
                "1,208,925,819,614,629,174,706,174",
                "2,417,851,639,229,258,349,412,350",
                "4,835,703,278,458,516,698,824,702",
                "9,671,406,556,917,033,397,649,406",
                "19,342,813,113,834,066,795,298,814",
                "38,685,626,227,668,133,590,597,630",
                "77,371,252,455,336,267,181,195,262",
                "154,742,504,910,672,534,362,390,526",
                "309,485,009,821,345,068,724,781,054",
                "618,970,019,642,690,137,449,562,110",
                "1,237,940,039,285,380,274,899,124,222",
                "2,475,880,078,570,760,549,798,248,446",
                "4,951,760,157,141,521,099,596,496,894",
                "9,903,520,314,283,042,199,192,993,790",
                "19,807,040,628,566,084,398,385,987,582",
                "39,614,081,257,132,168,796,771,975,166",
                "79,228,162,514,264,337,593,543,950,334",
                "158,456,325,028,528,675,187,087,900,670",
                "316,912,650,057,057,350,374,175,801,342",
                "633,825,300,114,114,700,748,351,602,686",
                "1,267,650,600,228,229,401,496,703,205,374",
                "2,535,301,200,456,458,802,993,406,410,750",
                "5,070,602,400,912,917,605,986,812,821,502",
                "10,141,204,801,825,835,211,973,625,643,006",
                "20,282,409,603,651,670,423,947,251,286,014",
                "40,564,819,207,303,340,847,894,502,572,030",
                "81,129,638,414,606,681,695,789,005,144,062",
                "162,259,276,829,213,363,391,578,010,288,126",
                "324,518,553,658,426,726,783,156,020,576,254",
                "649,037,107,316,853,453,566,312,041,152,510",
                "1,298,074,214,633,706,907,132,624,082,305,022",
                "2,596,148,429,267,413,814,265,248,164,610,046",
                "5,192,296,858,534,827,628,530,496,329,220,094",
                "10,384,593,717,069,655,257,060,992,658,440,190",
                "20,769,187,434,139,310,514,121,985,316,880,382",
                "41,538,374,868,278,621,028,243,970,633,760,766",
                "83,076,749,736,557,242,056,487,941,267,521,534",
                "166,153,499,473,114,484,112,975,882,535,043,070",
                "332,306,998,946,228,968,225,951,765,070,086,142",
                "664,613,997,892,457,936,451,903,530,140,172,286",
                "1,329,227,995,784,915,872,903,807,060,280,344,574",
                "2,658,455,991,569,831,745,807,614,120,560,689,150",
                "5,316,911,983,139,663,491,615,228,241,121,378,302",
                "10,633,823,966,279,326,983,230,456,482,242,756,606",
                "21,267,647,932,558,653,966,460,912,964,485,513,214",
                "42,535,295,865,117,307,932,921,825,928,971,026,430",
                "85,070,591,730,234,615,865,843,651,857,942,052,862",
                "170,141,183,460,469,231,731,687,303,715,884,105,726",
                "340,282,366,920,938,463,463,374,607,431,768,211,454"};

        return pow2m2;
    }


/* Create a network address */
    CIDR *
    cidr_addr_network (const CIDR *addr) {
        int i, j;
        CIDR *toret;

        /* Quick check */
        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */
        toret->proto = addr->proto;

        /* The netmask is the same */
        memcpy(toret->mask, addr->mask, (16 * sizeof(toret->mask[0])));

        /* Now just figure out the network address and spit it out */
        for (i = 0; i <= 15; i++) {
            for (j = 7; j >= 0; j--) {
                /* If we're into host bits, hop out */
                if ((addr->mask[i] & 1 << j) == 0)
                    return (toret);

                /* Else, copy this network bit */
                toret->addr[i] |= (addr->addr[i] & 1 << j);
            }
        }

        /*
     * We only get here on host (/32 or /128) addresses; shorter masks
     * return earlier.  But it's as correct as can be to just say the
     * same here, so...
     */
        return (toret);
    }


/* And a broadcast */
    CIDR *
    cidr_addr_broadcast (const CIDR *addr) {
        int i, j;
        CIDR *toret;

        /* Quick check */
        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */
        toret->proto = addr->proto;

        /* The netmask is the same */
        memcpy(toret->mask, addr->mask, (16 * sizeof(toret->mask[0])));

        /* Copy all the network bits */
        for (i = 0; i <= 15; i++) {
            for (j = 7; j >= 0; j--) {
                /* If we're into host bits, hop out */
                if ((addr->mask[i] & 1 << j) == 0)
                    goto post;

                /* Else, copy this network bit */
                toret->addr[i] |= (addr->addr[i] & 1 << j);

            }
        }

        post:
        /* Now set the remaining bits to 1 */
        for ( /* i */ ; i <= 15; i++) {
            for ( /* j */ ; j >= 0; j--)
                toret->addr[i] |= (1 << j);

            j = 7;
        }

        /* And send it back */
        return (toret);
    }


/* Get the first host in a CIDR block */
    CIDR *
    cidr_addr_hostmin (const CIDR *addr) {
        CIDR *toret;

        toret = cidr_addr_network(addr);
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */

        /* If it's a single host, the network addr is the [only] host */
        if (toret->mask[15] == 0xff)
            return (toret);

        /*
     * If it's a single host bit (/31 or /127), in a sense there are no
     * hosts at all.  But we presume that in the case of somebody
     * actually giving it, they're meaning it in a use like a PtP link
     * where they use both host addresses, so we'll go ahead and give
     * that 'network' address.
     */
        if (toret->mask[15] == 0xfe)
            return (toret);

        /* Else we bump up one from the network */
        toret->addr[15] |= 1;

        return (toret);
    }


/* Get the last host in a CIDR block */
    CIDR *
    cidr_addr_hostmax (const CIDR *addr) {
        CIDR *toret;

        toret = cidr_addr_broadcast(addr);
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */

        /* If it's a single host, the broadcast addr is the [only] host */
        if (toret->mask[15] == 0xff)
            return (toret);

        /*
     * See comment in cidr_addr_hostmin().  For /31 and /127, assume the
     * user really does want both addresses as hosts, so give 'em the
     * broadcast as the high 'host'.
     */
        if (toret->mask[15] == 0xfe)
            return (toret);

        /* Else we step down one */
        toret->addr[15] &= 0xfe;

        return (toret);
    }


/*
 * Various comparison functions
 */

/* Is one block entirely contained in another? */
    int
    cidr_contains (const CIDR *big, const CIDR *little) {
        int i, oct, bit;
        int pflen;

        /* Sanity */
        if (big == nullptr || little == nullptr) {
            errno = EFAULT;
            return (-1);
        }

        /* First off, they better be the same type */
        if (big->proto != little->proto) {
            errno = EPROTO;
            return (-1);
        }

        /* We better understand the protocol, too */
        if (big->proto != CIDR_IPV4 && big->proto != CIDR_IPV6) {
            errno = EINVAL;
            return (-1);
        }

        /*
     * little better be SMALL enough to fit in big.  Note: The prefix
     * lengths CAN be the same, and little could still 'fit' in big if
     * the network bits are all the same.  No need to special-case it, as
     * the normal tests below will DTRT.  Save big's pflen for the test
     * loop.
     */
        if (cidr_get_pflen(little) < (pflen = cidr_get_pflen(big))) {
            errno = 0;
            return (-1);
        }

        /*
     * Now let's compare.  Note that for IPv4 addresses, the first 12
     * octets are irrelevant.  We take care throughout to keep them
     * zero'd out, so we don't _need_ to explicitly ignore them.  But,
     * it's wasteful; it quadrules the amount of work needed to be done
     * to compare to v4 blocks, and this function may be useful in fairly
     * performance-sensitive parts of the application.  Sure, an extra 12
     * uint8_t compares better not be the make-or-break perforamnce point
     * for anything real, but why make it harder unnecessarily?
     */
        if (big->proto == CIDR_IPV4) {
            i = 96;
            pflen += 96;
        } else if (big->proto == CIDR_IPV6)
            i = 0;
        else {
            /* Shouldn't happen */
            errno = ENOENT; /* This is a really bad choice of errno */
            return (-1);
        }

        /* Start comparing */
        for ( /* i */ ; i < pflen; i++) {
            /* For convenience, set temp. vars to the octet/bit */
            oct = i / 8;
            bit = 7 - (i % 8);

            if ((big->addr[oct] & (1 << bit)) != (little->addr[oct] & (1 << bit))) {
                errno = 0;
                return (-1);
            }
        }

        /* If we get here, all their network bits are the same */
        return (0);
    }


/* Are two CIDR's the same? */
    int
    cidr_equals (const CIDR *one, const CIDR *two) {
        int i;

        /* Check protocols */
        if (one->proto != two->proto)
            return (-1);

        /* Check addresses/masks */
        if (one->proto == CIDR_IPV4)
            i = 12;
        else
            i = 0;
        for (/* i */ ; i <= 15; i++) {
            if (one->addr[i] != two->addr[i])
                return (-1);
            if (one->mask[i] != two->mask[i])
                return (-1);
        }

        /* If we make it here, they're the same */
        return (0);
    }


/*
 * cidr_from_str() - Generate a CIDR structure from a string in addr/len
 * form.
 */


    CIDR *
    cidr_from_str (const char *addr) {
        size_t _alen;
        int alen;
        CIDR *toret, *ctmp;
        const char *pfx, *buf;
        char *buf2; /* strtoul() can't use a (const char *) */
        int i, j;
        int pflen;
        unsigned long octet;
        int nocts, eocts;
        short foundpf, foundmask, nsect;

        /* There has to be *SOMETHING* to work with */
        if (addr == nullptr || (_alen = strlen(addr)) < 1) {
            errno = EFAULT;
            return (nullptr);
        }

        /*
     * But not too much.  The longest possible is a fully spelled out
     * IPv6 addr with a fully spelled out netmask (~80 char).  Let's
     * round way the heck up to 64k.
     */
        if (_alen > 1 << 16) {
            errno = EFAULT;
            return (nullptr);
        }
        alen = (int) _alen;

        /* And we know it can only contain a given set of chars */
        buf = addr + strspn(addr, "0123456789abcdefABCDEFxX.:/in-rpt");
        if (*buf != '\0') {
            errno = EINVAL;
            return (nullptr);
        }

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */


        /* First check if we're a PTR-style string */
        /*
     * XXX This could be folded with *pfx; they aren't used in code paths
     * that overlap.  I'm keeping them separate just to keep my sanity
     * though.
     */
        buf = nullptr;
        /* Handle the deprecated RFC1886 form of v6 PTR */
        if (strcasecmp(addr + alen - 8, ".ip6.int") == 0) {
            toret->proto = CIDR_IPV6;
            buf = addr + alen - 8;
        }

        if (buf != nullptr || strcasecmp(addr + alen - 5, ".arpa") == 0) {
            /*
         * Do all this processing here, instead of trying to intermix it
         * with the rest of the formats.  This might lead to some code
         * duplication, but it'll be easier to read.
         */
            if (buf == nullptr) /* If not set by .ip6.int above */
            {
                /* First, see what protocol it is */
                if (strncasecmp(addr + alen - 9, ".ip6", 3) == 0) {
                    toret->proto = CIDR_IPV6;
                    buf = addr + alen - 9;
                } else if (strncasecmp(addr + alen - 13, ".in-addr", 7) == 0) {
                    toret->proto = CIDR_IPV4;
                    buf = addr + alen - 13;
                } else {
                    /* Unknown */
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }
            }
            /*
         * buf now points to the period after the last (first) bit of
         * address numbering in the PTR name.
         */

            /*
         * Now convert based on that protocol.  Note that we're going to
         * be slightly asymmetrical to the way cidr_to_str() works, in
         * how we handle the netmask.  cidr_to_str() ignores it, and
         * treats the PTR-style output solely as host addresses.  We'll
         * use the netmask bits to specify how much of the address is
         * given in the PTR we get.  That is, if we get
         * "3.2.1.in-addr.arpa", we'll set a /24 netmask on the returned
         * result.  This way, the calling program can tell the difference
         * between "3.2.1..." and "0.3.2.1..." if it really cares to.
         */
            buf--; /* Step before the period */
            if (toret->proto == CIDR_IPV4) {
                for (i = 11; i <= 14; /* */) {
                    /* If we're before the beginning, we're done */
                    if (buf < addr)
                        break;

                    /* Step backward until we at the start of an octet */
                    while (isdigit(*buf) && buf >= addr)
                        buf--;

                    /*
                 * Save that number (++i here to show that this octet is
                 * now set.
                 */
                    octet = strtoul(buf + 1, nullptr, 10);
                    if (octet > (unsigned long) 0xff) {
                        /* Bad octet!  No biscuit! */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }
                    toret->addr[++i] = octet;


                    /*
                 * Back up a step to get before the '.', and process the
                 * next [previous] octet.  If we were at the beginning of
                 * the string already, the test at the top of the loop
                 * will drop us out.
                 */
                    buf--;
                }

                /* Too much? */
                if (buf >= addr) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                /*
             * Now, what about the mask?  We set the netmask bits to
             * describe how much information we've actually gotten, if we
             * didn't get all 4 octets.  Because of the way .in-addr.arpa
             * works, the mask can only fall on an octet boundary, so we
             * don't need too many fancy tricks.  'i' is still set from
             * the above loop to whatever the last octet we filled in is,
             * so we don't even have to special case anything.
             */
                for (j = 0; j <= i; j++)
                    toret->mask[j] = 0xff;

                /* Done processing */
            } else if (toret->proto == CIDR_IPV6) {
                /*
             * This processing happens somewhat similarly to IPV4 above,
             * the format is simplier, and we need to be a little
             * sneakier about the mask, since it can fall on a half-octet
             * boundary with .ip6.arpa format.
             */
                for (i = 0; i <= 15; i++) {
                    /* If we're before the beginning, we're done */
                    if (buf < addr)
                        break;

                    /* We better point at a number */
                    if (!isxdigit(*buf)) {
                        /* Bad input */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }

                    /* Save the current number */
                    octet = strtoul(buf, nullptr, 16);
                    if (octet > (unsigned long) 0xff) {
                        /* Bad octet!  No biscuit! */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }
                    toret->addr[i] = octet << 4;
                    toret->mask[i] = 0xf0;

                    /* If we're at the beginning of the string, we're thru */
                    if (buf == addr) {
                        /* Shift back to skip error condition at end of loop */
                        buf--;
                        break;
                    }

                    /* If we're not, stepping back should give us a period */
                    if (*--buf != '.') {
                        /* Bad input */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }

                    /* Stepping back again should give us a number */
                    if (!isxdigit(*--buf)) {
                        /* Bad input */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }

                    /* Save that one */
                    octet = strtoul(buf, nullptr, 16);
                    if (octet > (unsigned long) 0xff) {
                        /* Bad octet!  No biscuit! */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }
                    toret->addr[i] |= octet & 0x0f;
                    toret->mask[i] |= 0x0f;


                    /*
                 * Step back and loop back around.  If that last step
                 * back moves us to before the beginning of the string,
                 * the condition at the top of the loop will drop us out.
                 */
                    while (*--buf == '.' && buf >= addr)
                        /* nothing */;
                }

                /* Too much? */
                if (buf >= addr) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                /* Mask is set in the loop for v6 */
            } else {
                /* Shouldn't happen */
                cidr_free(toret);
                errno = ENOENT; /* Bad choice of errno */
                return (nullptr);
            }

            /* Return the value we built up, and we're done! */
            return (toret);

            /* NOTREACHED */
        }
        buf = nullptr; /* Done */


        /*
     * It's not a PTR form, so find the '/' prefix marker if we can.  We
     * support both prefix length and netmasks after the /, so flag if we
     * find a mask.
     */
        foundpf = foundmask = 0;
        for (i = alen - 1; i >= 0; i--) {
            /* Handle both possible forms of netmasks */
            if (addr[i] == '.' || addr[i] == ':')
                foundmask = 1;

            /* Are we at the beginning of the prefix? */
            if (addr[i] == '/') {
                foundpf = 1;
                break;
            }
        }

        if (foundpf == 0) {
            /* We didn't actually find a prefix, so reset the foundmask */
            foundmask = 0;

            /*
         * pfx is only used if foundpf==1, but set it to nullptr here to
         * quiet gcc down.
         */
            pfx = nullptr;
        } else {
            /* Remember where the prefix is */
            pfx = addr + i;

            if (foundmask == 0) {
                /*
             * If we didn't find a netmask, it may be that it's one of
             * the v4 forms without dots.  Technically, it COULD be
             * expressed as a single (32-bit) number that happens to be
             * between 0 and 32 inclusive, so there's no way to be
             * ABSOLUTELY sure when we have a prefix length and not a
             * netmask.  But, that would be a non-contiguous netmask,
             * which we don't attempt to support, so we can probably
             * safely ignore that case.  So try a few things...
             */
                /* If it's a hex or octal number, assume it's a mask */
                if (pfx[1] == '0' && tolower(pfx[2]) == 'x')
                    foundmask = 1; /* Hex */
                else if (pfx[1] == '0')
                    foundmask = 1; /* Oct */
                else if (isdigit(pfx[1])) {
                    /*
                 * If we get here, it looks like a decimal number, and we
                 * know there aren't any periods or colons in it, so if
                 * it's valid, it can ONLY be a single 32-bit decimal
                 * spanning the whole 4-byte v4 address range.  If that's
                 * true, it's GOTTA be a valid number, it's GOTTA reach
                 * to the end of the strong, and it's GOTTA be at least
                 * 2**31 and less than 2**32.
                 */
                    octet = strtoul(pfx + 1, &buf2, 10);
                    if (*buf2 == '\0' && octet >= (unsigned long) (1 << 31)
                        && octet <= (unsigned long) 0xffffffff)
                        foundmask = 1; /* Valid! */

                    octet = 0;
                    buf2 = nullptr; /* Done */
                }
            }
        }
        i = 0; /* Done */


        /*
     * Now, let's figure out what kind of address this is.  A v6 address
     * will contain a : within the first 5 characters ('0000:'), a v4
     * address will have a . within the first 4 ('123.'), UNLESS it's
     * just a single number (in hex, octal, or decimal).  Anything else
     * isn't an address we know anything about, so fail.
     */
        if ((buf = strchr(addr, ':')) != nullptr && (buf - addr) <= 5)
            toret->proto = CIDR_IPV6;
        else if ((buf = strchr(addr, '.')) != nullptr && (buf - addr) <= 4)
            toret->proto = CIDR_IPV4;
        else {
            /*
         * Special v4 forms
         */
            if (*addr == '0' && tolower(*(addr + 1)) == 'x') {
                /* Hex? */
                buf = (addr + 2) + strspn(addr + 2, "0123456789abcdefABCDEF");
                if (*buf == '\0' || *buf == '/')
                    toret->proto = CIDR_IPV4; /* Yep */
            } else if (*addr == '0') {
                /* Oct? */
                /* (note: this also catches the [decimal] address '0' */
                buf = (addr + 1) + strspn(addr + 1, "01234567");
                if (*buf == '\0' || *buf == '/')
                    toret->proto = CIDR_IPV4; /* Yep */
            } else {
                /* Dec? */
                buf = (addr) + strspn(addr, "0123456789");
                if (*buf == '\0' || *buf == '/')
                    toret->proto = CIDR_IPV4; /* Yep */
            }

            /* Did we catch anything? */
            if (toret->proto == 0) {
                /* Unknown */
                cidr_free(toret);
                errno = EINVAL;
                return (nullptr);
            }
        }
        buf = nullptr; /* Done */


        /*
     * So now we know what sort of address it is, we can go ahead and
     * have a parser for either.
     */
        if (toret->proto == CIDR_IPV4) {
            /*
         * Parse a v4 address.  Now, we're being a little tricksy here,
         * and parsing it from the end instead of from the front.
         */

            /*
         * First, find out how many bits we have.  We need to have 4 or
         * less...
         */
            buf = strchr(addr, '.');
            /* Through here, nsect counts dots */
            for (nsect = 0; buf != nullptr && (pfx != nullptr ? buf < pfx : 1); buf = strchr(buf, '.')) {
                nsect++; /* One more section */
                buf++; /* Move past . */
                if (nsect > 3) {
                    /* Bad!  We can't have more than 4 sections... */
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }
            }
            buf = nullptr; /* Done */
            nsect++; /* sects = dots+1 */

            /*
         * First, initialize this so we can skip building the bits if we
         * don't have to.
         */
            pflen = -1;

            /*
         * Initialize the first 12 octets of the address/mask to look
         * like a v6-mapped address.  This is the correct info for those
         * octets to have if/when we decide to use this v4 address as a
         * v6 one.
         */
            for (i = 0; i <= 9; i++)
                toret->addr[i] = 0;
            for (i = 10; i <= 11; i++)
                toret->addr[i] = 0xff;
            for (i = 0; i <= 11; i++)
                toret->mask[i] = 0xff;

            /*
         * Handle the prefix/netmask.  If it's not set at all, slam it to
         * the maximum, and put us at the end of the string to start out.
         * Ditto if the '/' is the end of the string.
         */
            if (foundpf == 0) {
                pflen = 32;
                i = alen - 1;
            } else if (foundpf == 1 && *(pfx + 1) == '\0') {
                pflen = 32;
                i = (int) (pfx - addr - 1);
            }

            /*
         * Or, if we found it, and it's a NETMASK, we need to parse it
         * just like an address.  So, cheat a little and call ourself
         * recursively, and then just count the bits in our returned
         * address for the pflen.
         */
            if (foundpf == 1 && foundmask == 1 && pflen == -1) {
                ctmp = cidr_from_str(pfx + 1);
                if (ctmp == nullptr) {
                    /* This shouldn't happen */
                    cidr_free(toret);
                    return (nullptr); /* Preserve errno */
                }
                /* Stick it in the mask */
                for (i = 0; i <= 11; i++)
                    ctmp->mask[i] = 0;
                for (i = 12; i <= 15; i++)
                    ctmp->mask[i] = ctmp->addr[i];

                /* Get our prefix length */
                pflen = cidr_get_pflen(ctmp);
                cidr_free(ctmp);
                if (pflen == -1) {
                    /* Failed; probably non-contiguous */
                    cidr_free(toret);
                    return (nullptr); /* Preserve errno */
                }

                /* And set us to before the '/' like below */
                i = (int) (pfx - addr - 1);
            }

            /*
         * Finally, if we did find it and it's a normal prefix length,
         * just pull it it, parse it out, and set ourselves to the first
         * character before the / for the address reading
         */
            if (foundpf == 1 && foundmask == 0 && pflen == -1) {
                pflen = (int) strtol(pfx + 1, nullptr, 10);
                i = (int) (pfx - addr - 1);
            }


            /*
         * If pflen is set, we need to turn it into a mask for the bits.
         * XXX pflen actually should ALWAYS be set, so we might not need
         * to make this conditional at all...
         */
            if (pflen > 0) {
                /* 0 < pflen <= 32 */
                if (pflen < 0 || pflen > 32) {
                    /* Always bad */
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                    /*
             * Now pflen is in the 0...32 range and thus good.  Set it in
             * the structure.  Note that memset zero'd the whole thing to
             * start.  We ignore mask[<12] with v4 addresses normally,
             * but they're already set to all-1 anyway, since if we ever
             * DO care about them, that's the most appropriate thing for
             * them to be.
             *
             * This is a horribly grody set of macros.  I'm only using
             * them here to test them out before using them in the v6
             * section, where I'll need them more due to the sheer number
             * of clauses I'll have to get written.  Here's the straight
             * code I had written that the macro should be writing for me
             * now:
             *
             * if(pflen>24)
             *   for(j=24 ; j<pflen ; j++)
             *     toret->mask[15] |= 1<<(31-j);
             * if(pflen>16)
             *   for(j=16 ; j<pflen ; j++)
             *     toret->mask[14] |= 1<<(23-j);
             * if(pflen>8)
             *   for(j=8 ; j<pflen ; j++)
             *     toret->mask[13] |= 1<<(15-j);
             * if(pflen>0)
             *   for(j=0 ; j<pflen ; j++)
             *     toret->mask[12] |= 1<<(7-j);
             */
#define UMIN(x, y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (24-((15-x)*8))
#define WRMASKSET(x) \
        if(pflen>MASKNUM(x)) \
            for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++) \
                toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

                WRMASKSET(15);
                WRMASKSET(14);
                WRMASKSET(13);
                WRMASKSET(12);

#undef WRMASKET
#undef MASKNUM
#undef UMIN
            } /* Normal v4 prefix */


            /*
         * Now we have 4 octets to grab.  If any of 'em fail, or are
         * outside the 0...255 range, bomb.
         */
            nocts = 0;

            /* Here, i should be before the /, but we may have multiple */
            while (i > 0 && addr[i] == '/')
                i--;

            for ( /* i */ ; i >= 0; i--) {
                /*
             * As long as it's still a number or an 'x' (as in '0x'),
             * keep backing up.  Could be hex, so don't just use
             * isdigit().
             */
                if ((isxdigit(addr[i]) || tolower(addr[i]) == 'x') && i > 0)
                    continue;

                /*
             * It's no longer a number.  So, grab the number we just
             * moved before.
             */
                /* Cheat for "beginning-of-string" rather than "NaN" */
                if (i == 0)
                    i--;
                /* Theoretically, this can be in hex/oct/dec... */
                if (addr[i + 1] == '0' && tolower(addr[i + 2]) == 'x')
                    octet = strtoul(addr + i + 1, &buf2, 16);
                else if (addr[i + 1] == '0')
                    octet = strtoul(addr + i + 1, &buf2, 8);
                else
                    octet = strtoul(addr + i + 1, &buf2, 10);

                /* If buf isn't pointing at one of [./'\0'], it's screwed */
                if (!(*buf2 == '.' || *buf2 == '/' || *buf2 == '\0')) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }
                buf2 = nullptr; /* Done */

                /*
             * Now, because of the way compressed IPv4 addresses work,
             * this number CAN be greater than 255, IF it's the last bit
             * in the address (the first bit we parse), in which case it
             * must be no bigger than needed to fill the unaccounted-for
             * 'slots' in the address.
             *
             * See
             * <http://www.opengroup.org/onlinepubs/007908799/xns/inet_addr.html>
             * for details.
             */
                if ((nocts != 0 && octet > 255)
                    || (nocts == 0 && octet > (0xffffffff >> (8 * (nsect - 1))))) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                /* Save the lower 8 bits into this octet */
                toret->addr[15 - nocts++] = octet & 0xff;

                /*
             * If this is the 'last' piece of the address (the first we
             * process), and there are fewer than 4 pieces total, we need
             * to extend it out into additional fields.  See above
             * reference.
             */
                if (nocts == 1) {
                    if (nsect <= 3)
                        toret->addr[15 - nocts++] = (octet >> 8) & 0xff;
                    if (nsect <= 2)
                        toret->addr[15 - nocts++] = (octet >> 16) & 0xff;
                    if (nsect == 1)
                        toret->addr[15 - nocts++] = (octet >> 24) & 0xff;
                }

                /*
             * If we've got 4 of 'em, we're actually done.  We got the
             * prefix above, so just return direct from here.
             */
                if (nocts == 4)
                    return (toret);
            }

            /*
         * If we get here, it failed to get all 4.  That shouldn't
         * happen, since we catch proper abbreviated forms above.
         */
            cidr_free(toret);
            errno = EINVAL;
            return (nullptr);
        } else if (toret->proto == CIDR_IPV6) {
            /*
         * Parse a v6 address.  Like the v4, we start from the end and
         * parse backward.  However, to handle compressed form, if we hit
         * a ::, we drop off and start parsing from the beginning,
         * because at the end we'll then have a hole that is what the ::
         * is supposed to contain, which is already automagically 0 from
         * the memset() we did earlier.  Neat!
         *
         * Initialize the prefix length
         */
            pflen = -1;

            /* If no prefix was found, assume the max */
            if (foundpf == 0) {
                pflen = 128;
                /* Stretch back to the end of the string */
                i = alen - 1;
            } else if (foundpf == 1 && *(pfx + 1) == '\0') {
                pflen = 128;
                i = (int) (pfx - addr - 1);
            }

            /*
         * If we got a netmask, rather than a prefix length, parse it and
         * count the bits, like we did for v4.
         */
            if (foundpf == 1 && foundmask == 1 && pflen == -1) {
                ctmp = cidr_from_str(pfx + 1);
                if (ctmp == nullptr) {
                    /* This shouldn't happen */
                    cidr_free(toret);
                    return (nullptr); /* Preserve errno */
                }
                /* Stick it in the mask */
                for (i = 0; i <= 15; i++)
                    ctmp->mask[i] = ctmp->addr[i];

                /* Get the prefix length */
                pflen = cidr_get_pflen(ctmp);
                cidr_free(ctmp);
                if (pflen == -1) {
                    /* Failed; probably non-contiguous */
                    cidr_free(toret);
                    return (nullptr); /* Preserve errno */
                }

                /* And set us to before the '/' like below */
                i = (int) (pfx - addr - 1);
            }

            /* Finally, the normal prefix case */
            if (foundpf == 1 && foundmask == 0 && pflen == -1) {
                pflen = (int) strtol(pfx + 1, nullptr, 10);
                i = (int) (pfx - addr - 1);
            }


            /*
         * Now, if we have a pflen, turn it into a mask.
         * XXX pflen actually should ALWAYS be set, so we might not need
         * to make this conditional at all...
         */
            if (pflen > 0) {
                /* Better be 0...128 */
                if (pflen < 0 || pflen > 128) {
                    /* Always bad */
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                    /*
             * Now save the pflen.  See comments on the similar code up in
             * the v4 section about the macros.
             */
#define UMIN(x, y) ((x)<(y)?(x):(y))
#define MASKNUM(x) (120-((15-x)*8))
#define WRMASKSET(x) \
        if(pflen>MASKNUM(x)) \
            for(j=MASKNUM(x) ; j<UMIN(pflen,MASKNUM(x)+8) ; j++) \
                toret->mask[x] |= 1<<(MASKNUM(x)+7-j);

                WRMASKSET(15);
                WRMASKSET(14);
                WRMASKSET(13);
                WRMASKSET(12);
                WRMASKSET(11);
                WRMASKSET(10);
                WRMASKSET(9);
                WRMASKSET(8);
                WRMASKSET(7);
                WRMASKSET(6);
                WRMASKSET(5);
                WRMASKSET(4);
                WRMASKSET(3);
                WRMASKSET(2);
                WRMASKSET(1);
                WRMASKSET(0);

#undef WRMASKET
#undef MASKNUM
#undef UMIN
            }


            /*
         * Now we have 16 octets to grab.  If any of 'em fail, or are
         * outside the 0...0xff range, bomb.  However, we MAY have a
         * v4-ish form, whether it's a formal v4 mapped/compat address,
         * or just a v4 address written in a v6 block.  So, look for
         * .-separated octets, but there better be exactly 4 of them
         * before we hit a :.
         */
            nocts = 0;

            /* Bump before / (or multiple /'s */
            while (i > 0 && addr[i] == '/')
                i--;

            for ( /* i */ ; i >= 0; i--) {
                /*
             * First, check the . cases, and handle them all in one
             * place.  These can only happen at the beginning, when we
             * have no octets yet, and if it happens at all, we need to
             * have 4 of them.
             */
                if (nocts == 0 && addr[i] == '.') {
                    i++; /* Shift back to after the '.' */

                    for ( /* i */ ; i > 0 && nocts < 4; i--) {
                        /* This shouldn't happen except at the end */
                        if (addr[i] == ':' && nocts < 3) {
                            cidr_free(toret);
                            errno = EINVAL;
                            return (nullptr);
                        }

                        /* If it's not a . or :, move back 1 */
                        if (addr[i] != '.' && addr[i] != ':')
                            continue;

                        /* Should be a [decimal] octet right after here */
                        octet = strtoul(addr + i + 1, nullptr, 10);
                        /* Be sure */
                        if (octet > 255) {
                            cidr_free(toret);
                            errno = EINVAL;
                            return (nullptr);
                        }

                        /* Save it */
                        toret->addr[15 - nocts] = octet & 0xff;
                        nocts++;

                        /* And find the next octet */
                    }

                    /*
                 * At this point, 4 dotted-decimal octets should be
                 * consumed.  i has gone back one step past the : before
                 * the decimal, so addr[i+1] should be the ':' that
                 * preceeds them.  Verify.
                 */
                    if (nocts != 4 || addr[i + 1] != ':') {
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }
                }

                /*
             * Now we've either gotten 4 octets filled in from
             * dotted-decimal stuff, or we've filled in nothing and have
             * no dotted decimal.
             */


                /* As long as it's not our separator, keep moving */
                if (addr[i] != ':' && i > 0)
                    continue;

                /* If it's a :, and our NEXT char is a : too, flee */
                if (addr[i] == ':' && addr[i + 1] == ':') {
                    /*
                 * If i is 0, we're already at the beginning of the
                 * string, so we can just return; we've already filled in
                 * everything but the leading 0's, which are already
                 * zero-filled from the memory
                 */
                    if (i == 0)
                        return (toret);

                    /* Else, i!=0, and we break out */
                    break;
                }

                /* If it's not a number either...   well, bad data */
                if (!isxdigit(addr[i]) && addr[i] != ':' && i > 0) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                /*
             * It's no longer a number.  So, grab the number we just
             * moved before.
             */
                /* Cheat for "beginning-of-string" rather than "NaN" */
                if (i == 0)
                    i--;
                octet = strtoul(addr + i + 1, &buf2, 16);
                if (*buf2 != ':' && *buf2 != '/' && *buf2 != '\0') {
                    /* Got something unexpected */
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }
                buf2 = nullptr;

                /* Remember, this is TWO octets */
                if (octet > 0xffff) {
                    cidr_free(toret);
                    errno = EINVAL;
                    return (nullptr);
                }

                /* Save it */
                toret->addr[15 - nocts] = octet & 0xff;
                nocts++;
                toret->addr[15 - nocts] = (octet >> 8) & 0xff;
                nocts++;

                /* If we've got all of 'em, just return from here. */
                if (nocts == 16)
                    return (toret);
            }

            /*
         * Now, if i is >=0 and we've got two :'s, jump around to the
         * front of the string and start parsing inward.
         */
            if (i >= 0 && addr[i] == ':' && addr[i + 1] == ':') {
                /* Remember how many octets we put on the end */
                eocts = nocts;

                /* Remember how far we were into the string */
                j = i;

                /* Going this way, we do things a little differently */
                i = 0;
                while (i < j) {
                    /*
                 * The first char better be a number.  If it's not, bail
                 * (a leading '::' was already handled in the loop above
                 * by just returning).
                 */
                    if (i == 0 && !isxdigit(addr[i])) {
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }

                    /*
                 * We should be pointing at the beginning of a digit
                 * string now.  Translate it into an octet.
                 */
                    octet = strtoul(addr + i, &buf2, 16);
                    if (*buf2 != ':' && *buf2 != '/' && *buf2 != '\0') {
                        /* Got something unexpected */
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }
                    buf2 = nullptr;

                    /* Sanity (again, 2 octets) */
                    if (octet > 0xffff) {
                        cidr_free(toret);
                        errno = EINVAL;
                        return (nullptr);
                    }

                    /* Save it */
                    toret->addr[nocts - eocts] = (octet >> 8) & 0xff;
                    nocts++;
                    toret->addr[nocts - eocts] = octet & 0xff;
                    nocts++;

                    /*
                 * Discussion: If we're in this code block, it's because
                 * we hit a ::-compression while parsing from the end
                 * backward.  So, if we hit 15 octets here, it's an
                 * error, because with the at-least-2 that were minimized,
                 * that makes 17 total, which is too many.  So, error
                 * out.
                 */
                    if (nocts == 15) {
                        cidr_free(toret);
                        return (nullptr);
                    }

                    /* Now skip around to the end of this number */
                    while (isxdigit(addr[i]) && i < j)
                        i++;

                    /*
                 * If i==j, we're back where we started.  So we've filled
                 * in all the leading stuff, and the struct is ready to
                 * return.
                 */
                    if (i == j)
                        return (toret);

                    /*
                 * Else, there's more to come.  We better be pointing at
                 * a ':', else die.
                 */
                    if (addr[i] != ':') {
                        cidr_free(toret);
                        return (nullptr);
                    }

                    /* Skip past : */
                    i++;

                    /* If we're at j now, we had a ':::', which is invalid */
                    if (i == j) {
                        cidr_free(toret);
                        return (nullptr);
                    }

                    /* Head back around */
                }
            }

            /* If we get here, it failed somewhere odd */
            cidr_free(toret);
            errno = EINVAL;
            return (nullptr);
        } else {
            /* Shouldn't happen */
            cidr_free(toret);
            errno = ENOENT; /* Bad choice of errno */
            return (nullptr);
        }
    }


/*
 * cidr_get - Get and return various semi-raw bits of info
 */



/* Get the prefix length */
    int
    cidr_get_pflen (const CIDR *block) {
        int i, j;
        int foundnmh;
        int pflen;

        if (block == nullptr) {
            errno = EFAULT;
            return (-1);
        }

        /* Where do we start? */
        if (block->proto == CIDR_IPV4)
            i = 12;
        else if (block->proto == CIDR_IPV6)
            i = 0;
        else {
            errno = ENOENT; /* Bad errno */
            return (-1); /* Unknown */
        }

        /*
     * We're intentionally not supporting non-contiguous netmasks.  So,
     * if we find one, bomb out.
     */
        foundnmh = 0;
        pflen = 0;
        for (/* i */ ; i <= 15; i++) {
            for (j = 7; j >= 0; j--) {
                if ((block->mask)[i] & (1 << j)) {
                    /*
                 * This is a network bit (1).  If we've already seen a
                 * host bit (0), we need to bomb.
                 */
                    if (foundnmh == 1) {
                        errno = EINVAL;
                        return (-1);
                    }

                    pflen++;
                } else
                    foundnmh = 1; /* A host bit */
            }
        }

        /* If we get here, return the length */
        return (pflen);
    }


/* Get the address bits */
    uint8_t *
    cidr_get_addr (const CIDR *addr) {
        uint8_t *toret;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = (uint8_t *) malloc(16 * sizeof(uint8_t));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }

        /* Copy 'em in */
        memcpy(toret, addr->addr, sizeof(addr->addr));

        return (toret);
    }


/* Get the netmask bits */
    uint8_t *
    cidr_get_mask (const CIDR *addr) {
        uint8_t *toret;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = (uint8_t *) malloc(16 * sizeof(uint8_t));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }

        /* Copy 'em in */
        memcpy(toret, addr->mask, sizeof(addr->mask));

        return (toret);
    }


/* Get the protocol */
    int
    cidr_get_proto (const CIDR *addr) {

        if (addr == nullptr) {
            errno = EFAULT;
            return (-1);
        }

        return (addr->proto);
    }


/*
 * Functions to convert to/from in[6]_addr structs
 */


/* Create a struct in_addr with the given v4 address */
    struct in_addr *
    cidr_to_inaddr (const CIDR *addr, struct in_addr *uptr) {
        struct in_addr *toret;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        /* Better be a v4 address... */
        if (addr->proto != CIDR_IPV4) {
            errno = EPROTOTYPE;
            return (nullptr);
        }

        /*
     * Use the user's struct if possible, otherwise allocate one.  It's
     * _their_ responsibility to give us the right type of struct to not
     * stomp all over the address space...
     */
        toret = uptr;
        if (toret == nullptr)
            toret = (in_addr *) malloc(sizeof(struct in_addr));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }
        memset(toret, 0, sizeof(struct in_addr));

        /* Add 'em up and stuff 'em in */
        toret->s_addr = ((addr->addr)[12] << 24)
                        + ((addr->addr)[13] << 16)
                        + ((addr->addr)[14] << 8)
                        + ((addr->addr)[15]);

        /*
     * in_addr's are USUALLY used inside sockaddr_in's to do socket
     * stuff.  The upshot of this is that they generally need to be in
     * network byte order.  We'll do that transition here; if the user
     * wants to be different, they'll have to manually convert.
     */
        toret->s_addr = htonl(toret->s_addr);

        return (toret);
    }


/* Build up a CIDR struct from a given in_addr */
    CIDR *
    cidr_from_inaddr (const struct in_addr *uaddr) {
        int i;
        CIDR *toret;
        in_addr_t taddr;

        if (uaddr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */
        toret->proto = CIDR_IPV4;

        /*
     * For IPv4, pretty straightforward, except that we need to jump
     * through a temp variable to convert into host byte order.
     */
        taddr = ntohl(uaddr->s_addr);

        /* Mask these just to be safe */
        toret->addr[15] = (taddr & 0xff);
        toret->addr[14] = ((taddr >> 8) & 0xff);
        toret->addr[13] = ((taddr >> 16) & 0xff);
        toret->addr[12] = ((taddr >> 24) & 0xff);

        /* Give it a single-host mask */
        toret->mask[15] = toret->mask[14] =
        toret->mask[13] = toret->mask[12] = 0xff;

        /* Standard v4 overrides of addr and mask for mapped form */
        for (i = 0; i <= 9; i++)
            toret->addr[i] = 0;
        for (i = 10; i <= 11; i++)
            toret->addr[i] = 0xff;
        for (i = 0; i <= 11; i++)
            toret->mask[i] = 0xff;

        /* That's it */
        return (toret);
    }


/* Create a struct in5_addr with the given v6 address */
    struct in6_addr *
    cidr_to_in6addr (const CIDR *addr, struct in6_addr *uptr) {
        struct in6_addr *toret;
        int i;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        /*
     * Note: We're allowing BOTH IPv4 and IPv6 addresses to go through
     * this function.  The reason is that this allows us to build up an
     * in6_addr struct to be used to connect to a v4 host (via a
     * v4-mapped address) through a v6 socket connection.  A v4
     * cidr_address, when built, has the upper bits of the address set
     * correctly for this to work.  We don't support "compat"-mode
     * addresses here, though, and won't.
     */
        if (addr->proto != CIDR_IPV6 && addr->proto != CIDR_IPV4) {
            errno = EPROTOTYPE;
            return (nullptr);
        }

        /* Use their struct if they gave us one */
        toret = uptr;
        if (toret == nullptr)
            toret = (in6_addr *) malloc(sizeof(struct in6_addr));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }
        memset(toret, 0, sizeof(struct in6_addr));

        /*
     * The in6_addr is defined to store it in 16 octets, just like we do.
     * But just to be safe, we're not going to stuff a giant copy in.
     * Most systems also use some union trickery to force alignment, but
     * we don't need to worry about that.
     * Now, this is defined to be in network byte order, which is
     * MSB-first.  Since this is a structure of bytes, and we're filling
     * them in from the MSB onward ourself, we don't actually have to do
     * any conversions.
     */
        for (i = 0; i <= 15; i++)
            toret->s6_addr[i] = addr->addr[i];

        return (toret);
    }


/* And create up a CIDR struct from a given in6_addr */
    CIDR *
    cidr_from_in6addr (const struct in6_addr *uaddr) {
        int i;
        CIDR *toret;

        if (uaddr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */
        toret->proto = CIDR_IPV6;

        /*
     * For v6, just iterate over the arrays and return.  Set all 1's in
     * the mask while we're at it, since this is a single host.
     */
        for (i = 0; i <= 15; i++) {
            toret->addr[i] = uaddr->s6_addr[i];
            toret->mask[i] = 0xff;
        }

        return (toret);
    }

/*
 * Various libcidr memory-related functions
 */

/* Allocate a struct cidr_addr */
    CIDR *
    cidr_alloc () {
        CIDR *toret;

        toret = (CIDR *) malloc(sizeof(CIDR));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }
        memset(toret, 0, sizeof(CIDR));

        return (toret);
    }


/* Duplicate a CIDR */
    CIDR *
    cidr_dup (const CIDR *src) {
        CIDR *toret;

        toret = cidr_alloc();
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */
        memcpy(toret, src, sizeof(CIDR));

        return (toret);
    }


/* Free a struct cidr_addr */
    void
    cidr_free (CIDR *tofree) {

        free(tofree);
    }

/*
 * Misc pieces
 */



/* Library version info */
    const char* cidr_version () {
        static const char *libcidr_version = CIDR_VERSION_STR;
        return (libcidr_version);
    }


/* Is a CIDR a v4-mapped IPv6 address? */
    int
    cidr_is_v4mapped (const CIDR *addr) {
        int i;

        if (addr->proto != CIDR_IPV6)
            return (-1);

        /* First 10 octets should be 0 */
        for (i = 0; i <= 9; i++)
            if (addr->addr[i] != 0)
                return (-1);

        /* Next 2 should be 0xff */
        for (i = 10; i <= 11; i++)
            if (addr->addr[i] != 0xff)
                return (-1);

        /* Then it is */
        return (0);
    }

/*
 * Functions to generate various networks based on a CIDR
 */


/* Get the CIDR's immediate supernet */
    CIDR *
    cidr_net_supernet (const CIDR *addr) {
        int i, j;
        int pflen;
        CIDR *toret;

        /* Quick check */
        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        /* If it's already a /0 in its protocol, return nothing */
        pflen = cidr_get_pflen(addr);
        if (pflen == 0) {
            errno = 0;
            return (nullptr);
        }

        toret = cidr_dup(addr);
        if (toret == nullptr)
            return (nullptr); /* Preserve errno */

        /* Chop a bit off the netmask */
        /* This gets the last network bit */
        if (toret->proto == CIDR_IPV4)
            pflen += 96;
        pflen--;
        i = pflen / 8;
        j = 7 - (pflen % 8);

        /* Make that bit a host bit */
        (toret->mask)[i] &= ~(1 << j);

        /*
     * Now zero out the host bits in the addr.  Do this manually instead
     * of calling cidr_addr_network() to save some extra copies and
     * malloc()'s and so forth.
     */
        for (/* i */ ; i <= 15; i++) {
            for (/* j */ ; j >= 0; j--)
                (toret->addr)[i] &= ~(1 << j);
            j = 7;
        }

        /* And send it back */
        return (toret);
    }


/* Get the CIDR's two children */
    CIDR **
    cidr_net_subnets (const CIDR *addr) {
        int i, j;
        int pflen;
        CIDR **toret;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        /* You can't split a host address! */
        pflen = cidr_get_pflen(addr);
        if ((addr->proto == CIDR_IPV4 && pflen == 32)
            || (addr->proto == CIDR_IPV6 && pflen == 128)) {
            errno = 0;
            return (nullptr);
        }

        toret = (CIDR **) malloc(2 * sizeof(CIDR *));
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }

        /* Get a blank-ish slate for the first kid */
        toret[0] = cidr_addr_network(addr);
        if (toret[0] == nullptr) {
            free(toret);
            return (nullptr); /* Preserve errno */
        }

        /* Find its first host bit */
        if (toret[0]->proto == CIDR_IPV4)
            pflen += 96;
        i = pflen / 8;
        j = 7 - (pflen % 8);

        /* Make it a network bit */
        (toret[0])->mask[i] |= 1 << j;

        /* Now dup the second kid off that */
        toret[1] = cidr_dup(toret[0]);
        if (toret[1] == nullptr) {
            cidr_free(toret[0]);
            free(toret);
            return (nullptr); /* Preserve errno */
        }

        /* And set that first host bit */
        (toret[1])->addr[i] |= 1 << j;


        /* Return the pair */
        return (toret);
    }

/*
 * Show some numbers
 */


/* Number of total addresses in a given prefix length */
    const char *
    cidr_numaddr_pflen (int pflen) {

        if (pflen < 0 || pflen > 128) {
            errno = EINVAL;
            return (nullptr);
        }
        return (cidr_pow2()[128 - pflen]);
    }


/* Addresses in a CIDR block */
    const char *
    cidr_numaddr (const CIDR *addr) {
        int pflen;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        pflen = cidr_get_pflen(addr);
        if (addr->proto == CIDR_IPV4)
            pflen += 96;

        return (cidr_numaddr_pflen(pflen));
    }


/* Hosts in a prefix length */
    const char *
    cidr_numhost_pflen (int pflen) {

        if (pflen < 0 || pflen > 128) {
            errno = EINVAL;
            return (nullptr);
        }
        return (cidr_pow2m2()[128 - pflen]);
    }


/* Addresses in a CIDR block */
    const char *
    cidr_numhost (const CIDR *addr) {
        int pflen;

        if (addr == nullptr) {
            errno = EFAULT;
            return (nullptr);
        }

        pflen = cidr_get_pflen(addr);
        if (addr->proto == CIDR_IPV4)
            pflen += 96;

        return (cidr_numhost_pflen(pflen));
    }

/*
 * cidr_to_str() - Generate a textual representation of the given CIDR
 * subnet.
 */

    char *
    cidr_to_str (const CIDR *block, int flags) {
        int i;
        int zst, zcur, zlen, zmax;
        short pflen;
        short lzer; /* Last zero */
        char *toret;
        constexpr unsigned int tmpbuf_sz = 128;
        char tmpbuf[tmpbuf_sz]; /* We shouldn't need more than ~5 anywhere */
        CIDR *nmtmp;
        char *nmstr;
        int nmflags;
        uint8_t moct;
        uint16_t v6sect;

        /* Just in case */
        if ((block == nullptr) || (block->proto == CIDR_NOPROTO)) {
            errno = EINVAL;
            return (nullptr);
        }

        /*
     * Sanity: If we have both ONLYADDR and ONLYPFLEN, we really don't
     * have anything to *DO*...
     */
        if ((flags & CIDR_ONLYADDR) && (flags & CIDR_ONLYPFLEN)) {
            errno = EINVAL;
            return (nullptr);
        }

        /*
     * Now, in any case, there's a maximum length for any address, which
     * is the completely expanded form of a v6-{mapped,compat} address
     * with a netmask instead of a prefix.  That's 8 pieces of 4
     * characters each (32), separated by :'s (+7=39), plus the slash
     * (+1=40), plus another separated-8*4 (+39=79), plus the trailing
     * null (+1=80).  We'll just allocate 128 for kicks.
     *
     * I'm not, at this time anyway, going to try and allocate only and
     * exactly as much as we need for any given address.  Whether
     * consumers of the library can count on this behavior...  well, I
     * haven't decided yet.  Lemme alone.
     */
        toret = (char *) malloc(128);
        if (toret == nullptr) {
            errno = ENOMEM;
            return (nullptr);
        }
        memset(toret, 0, 128);

        /*
     * If it's a v4 address, we mask off everything but the last 4
     * octets, and just proceed from there.
     */
        if ((block->proto == CIDR_IPV4 && !(flags & CIDR_FORCEV6))
            || (flags & CIDR_FORCEV4)) {
            /* First off, creating the in-addr.arpa form is special */
            if (flags & CIDR_REVERSE) {
                /*
             * Build the d.c.b.a.in-addr.arpa form.  Note that we ignore
             * flags like CIDR_VERBOSE and the like here, since they lead
             * to non-valid reverse paths (or at least, paths that no DNS
             * implementation will look for).  So it pretty much always
             * looks exactly the same.  Also, we don't mess with dealing
             * with netmaks or anything here; we just assume it's a
             * host address, and treat it as such.
             */

                sprintf(toret, "%d.%d.%d.%d.in-addr.arpa",
                        block->addr[15], block->addr[14],
                        block->addr[13], block->addr[12]);
                return (toret);
            }

            /* Are we bothering to show the address? */
            if (!(flags & CIDR_ONLYPFLEN)) {
                /* If we're USEV6'ing, add whatever prefixes we need */
                if (flags & CIDR_USEV6) {
                    if (flags & CIDR_NOCOMPACT) {
                        if (flags & CIDR_VERBOSE)
                            strcat(toret, "0000:0000:0000:0000:0000:");
                        else
                            strcat(toret, "0:0:0:0:0:");
                    } else
                        strcat(toret, "::");

                    if (flags & CIDR_USEV4COMPAT) {
                        if (flags & CIDR_NOCOMPACT) {
                            if (flags & CIDR_VERBOSE)
                                strcat(toret, "0000:");
                            else
                                strcat(toret, "0:");
                        }
                    } else
                        strcat(toret, "ffff:");
                } /* USEV6 */

                /* Now, slap on the v4 address */
                for (i = 12; i <= 15; i++) {
                    sprintf(tmpbuf, "%u", (block->addr)[i]);
                    strncat(toret, tmpbuf, tmpbuf_sz - 1);
                    if (i < 15)
                        strcat(toret, ".");
                }
            } /* ! ONLYPFLEN */

            /* Are we bothering to show the pf/mask? */
            if (!(flags & CIDR_ONLYADDR)) {
                /*
             * And the prefix/netmask.  Don't show the '/' if we're only
             * showing the pflen/mask.
             */
                if (!(flags & CIDR_ONLYPFLEN))
                    strcat(toret, "/");

                /* Which are we showing? */
                if (flags & CIDR_NETMASK) {
                    /*
                 * In this case, we can just print out like the address
                 * above.
                 */
                    for (i = 12; i <= 15; i++) {
                        moct = (block->mask)[i];
                        if (flags & CIDR_WILDCARD)
                            moct = ~(moct);
                        sprintf(tmpbuf, "%u", moct);
                        strncat(toret, tmpbuf, tmpbuf_sz - 1);
                        if (i < 15)
                            strcat(toret, ".");
                    }
                } else {
                    /*
                 * For this, iterate over each octet,
                 * then each bit within the octet.
                 */
                    pflen = cidr_get_pflen(block);
                    if (pflen == -1) {
                        free(toret);
                        return (nullptr); /* Preserve errno */
                    }
                    /* Special handling for forced modes */
                    if (block->proto == CIDR_IPV6 && (flags & CIDR_FORCEV4))
                        pflen -= 96;

                    sprintf(tmpbuf, "%u",
                            (flags & CIDR_USEV6) ? pflen + 96 : pflen);

                    strncat(toret, tmpbuf, tmpbuf_sz - 1);
                }
            } /* ! ONLYADDR */

            /* That's it for a v4 address, in any of our forms */
        } else if ((block->proto == CIDR_IPV6 && !(flags & CIDR_FORCEV4))
                   || (flags & CIDR_FORCEV6)) {
            /* First off, creating the .ip6.arpa form is special */
            if (flags & CIDR_REVERSE) {
                /*
             * Build the ...ip6.arpa form.  See notes in the CIDR_REVERSE
             * section of PROTO_IPV4 above for various notes.
             */
                sprintf(toret, "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                               "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
                               "%x.%x.%x.%x.%x.ip6.arpa",
                        block->addr[15] & 0x0f, block->addr[15] >> 4,
                        block->addr[14] & 0x0f, block->addr[14] >> 4,
                        block->addr[13] & 0x0f, block->addr[13] >> 4,
                        block->addr[12] & 0x0f, block->addr[12] >> 4,
                        block->addr[11] & 0x0f, block->addr[11] >> 4,
                        block->addr[10] & 0x0f, block->addr[10] >> 4,
                        block->addr[9] & 0x0f, block->addr[9] >> 4,
                        block->addr[8] & 0x0f, block->addr[8] >> 4,
                        block->addr[7] & 0x0f, block->addr[7] >> 4,
                        block->addr[6] & 0x0f, block->addr[6] >> 4,
                        block->addr[5] & 0x0f, block->addr[5] >> 4,
                        block->addr[4] & 0x0f, block->addr[4] >> 4,
                        block->addr[3] & 0x0f, block->addr[3] >> 4,
                        block->addr[2] & 0x0f, block->addr[2] >> 4,
                        block->addr[1] & 0x0f, block->addr[1] >> 4,
                        block->addr[0] & 0x0f, block->addr[0] >> 4);
                return (toret);
            }
            /* Are we showing the address part? */
            if (!(flags & CIDR_ONLYPFLEN)) {
                /* It's a simple, boring, normal v6 address */

                /* First, find the longest string of 0's, if there is one */
                zst = zcur = -1;
                zlen = zmax = 0;
                for (i = 0; i <= 15; i += 2) {
                    if (block->addr[i] == 0 && block->addr[i + 1] == 0) {
                        /* This section is zero */
                        if (zcur != -1) {
                            /* We're already in a block of 0's */
                            zlen++;
                        } else {
                            /* Starting a new block */
                            zcur = i;
                            zlen = 1;
                        }
                    } else {
                        /* This section is non-zero */
                        if (zcur != -1) {
                            /*
                         * We were in 0's.  See if we set a new record,
                         * and if we did, note it and move on.
                         */
                            if (zlen > zmax) {
                                zst = zcur;
                                zmax = zlen;
                            }

                            /* We're out of 0's, so reset start */
                            zcur = -1;
                        }
                    }
                }

                /*
             * If zcur is !=-1, we were in 0's when the loop ended.  Redo
             * the "if we have a record, update" logic.
             */
                if (zcur != -1 && zlen > zmax) {
                    zst = zcur;
                    zmax = zlen;
                }


                /*
             * Now, what makes it HARD is the options we have.  To make
             * some things simpler, we'll take two octets at a time for
             * our run through.
             */
                lzer = 0;
                for (i = 0; i <= 15; i += 2) {
                    /*
                 * Start with a cheat; if this begins our already-found
                 * longest block of 0's, and we're not NOCOMPACT'ing,
                 * stick in a ::, increment past them, and keep on
                 * playing.
                 */
                    if (i == zst && !(flags & CIDR_NOCOMPACT)) {
                        strcat(toret, "::");
                        i += (zmax * 2) - 2;
                        lzer = 1;
                        continue;
                    }

                    /*
                 * First, if we're not the first set, we may need a :
                 * before us.  If we're not compacting, we always want
                 * it.  If we ARE compacting, we want it unless the
                 * previous octet was a 0 that we're minimizing.
                 */
                    if (i != 0 && ((flags & CIDR_NOCOMPACT) || lzer == 0))
                        strcat(toret, ":");
                    lzer = 0; /* Reset */

                    /*
                 * From here on, we no longer have to worry about
                 * CIDR_NOCOMPACT.
                 */

                    /* Combine the pair of octets into one number */
                    v6sect = 0;
                    v6sect |= (block->addr)[i] << 8;
                    v6sect |= (block->addr)[i + 1];

                    /*
                 * If we're being VERBOSE, use leading 0's.  Otherwise,
                 * only use as many digits as we need.
                 */
                    if (flags & CIDR_VERBOSE)
                        sprintf(tmpbuf, "%.4x", v6sect);
                    else
                        sprintf(tmpbuf, "%x", v6sect);
                    strncat(toret, tmpbuf, tmpbuf_sz - 1);

                    /* And loop back around to the next 2-octet set */
                } /* for(each 16-bit set) */
            } /* ! ONLYPFLEN */

            /* Prefix/netmask */
            if (!(flags & CIDR_ONLYADDR)) {
                /* Only show the / if we're not showing just the prefix */
                if (!(flags & CIDR_ONLYPFLEN))
                    strcat(toret, "/");

                if (flags & CIDR_NETMASK) {
                    /*
                 * We already wrote how to build the whole v6 form, so
                 * just call ourselves recurively for this.
                 */
                    nmtmp = cidr_alloc();
                    if (nmtmp == nullptr) {
                        free(toret);
                        return (nullptr); /* Preserve errno */
                    }
                    nmtmp->proto = block->proto;
                    for (i = 0; i <= 15; i++)
                        if (flags & CIDR_WILDCARD)
                            nmtmp->addr[i] = ~(block->mask[i]);
                        else
                            nmtmp->addr[i] = block->mask[i];

                    /*
                 * Strip flags:
                 * - CIDR_NETMASK would make us recurse forever.
                 * - CIDR_ONLYPFLEN would not show the address bit, which
                 *   is the part we want here.
                 * Add flag CIDR_ONLYADDR because that's the bit we care
                 * about.
                 */
                    nmflags = flags;
                    nmflags &= ~(CIDR_NETMASK) & ~(CIDR_ONLYPFLEN);
                    nmflags |= CIDR_ONLYADDR;
                    nmstr = cidr_to_str(nmtmp, nmflags);
                    cidr_free(nmtmp);
                    if (nmstr == nullptr) {
                        free(toret);
                        return (nullptr); /* Preserve errno */
                    }

                    /* No need to strip the prefix, it doesn't have it */

                    /* Just add it on */
                    strncat(toret, nmstr, tmpbuf_sz - 1);
                    free(nmstr);
                } else {
                    /* Just figure the and show prefix length */
                    pflen = cidr_get_pflen(block);
                    if (pflen == -1) {
                        free(toret);
                        return (nullptr); /* Preserve errno */
                    }
                    /* Special handling for forced modes */
                    if (block->proto == CIDR_IPV4 && (flags & CIDR_FORCEV6))
                        pflen += 96;

                    sprintf(tmpbuf, "%u", pflen);
                    strncat(toret, tmpbuf,  tmpbuf_sz - 1);
                }
            } /* ! ONLYADDR */
        } else {
            /* Well, *I* dunno what the fuck it is */
            free(toret);
            errno = ENOENT; /* Bad choice of errno */
            return (nullptr);
        }

        /* Give back the string */
        return (toret);
    }

}