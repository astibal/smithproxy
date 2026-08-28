#include <iostream>
#include <vector>
#include <cstdint>
#include <optional>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include <gtest/gtest.h>

#include "src/inspect/fp/ja4.hpp"

using namespace sx::ja4;



// ClientHello samples

const std::string raw_str_1 = "010002880303b1454f846bd902745d988d870726ef0c313ce90f17984d51557964c3e606fa91200b509f238e6769dd3ad25fe6ed13020e3f7b64738a226fc0158ef2b59ba19b2c0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100021d0000000e000c0000096a613464622e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d0020cb5494b8b6fffd904f2c18eecc978ae6ef7c9c89d347498dae1b66799176554900170041040bbdc463c55494edca30649e6c48e51261c4d61843e7cf607fffddca1d7cf7d8ae69ced9796f6403565655906bbcd7dffc103db95889d5d6774114b6793c4132002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001fe0d01190000010003d10020b8cdfd2a9b9924e45471c4ebb24514d71a231a49d8d314fbcb75af0214a2e67c00efd356cf2704ea9bb5e85579856bf473cb9b5ae1657b33929c86f5ee4b57cafcac74ecb8fe201f5d9e883efdd391395639d9e42eafa8eae467601838c23c3e239907da1a6983f4e966e4990ff13f74e0159fe37d60535b76d308caea1e114170ce3e3fd67c14a2f5e3e8fe540895e3d6a66fec86e88d2e403f9ff299681748c664572a7e889fe274ec142b2f5eb9445142c16dd98034f92d47be96ead6b030536ca37506cc44c94fd7d1f1b2178b71d5fc5e5339b1c91cf9db67c82099a0f0168ce228947c600a1cd48ee9d9b481c87f052999431bd4b91d2aac4a7dab3090578a64087a3d7cd9c603c6e75c7d878f9d";
const char* JA4_r_1 = "t13d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201";
const char* JA4_1 = "t13d1715h2_5b57614c22b0_5c2c66f702b0";

const std::string raw_str_2 = "010009840303e4b7a5b2fad5e8737ea991ab7c256c0a9aca8f9873f9ca6ee6cb9bb81eabe288203ef59a4c461b0376f49d2ed9557ae6f08a54e37beee7b11f05d06b2341ecce560022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010009190000000e000c0000096a613464622e636f6d00170000ff01000100000a0010000e11ec001d00170018001901000101000b000201000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033052f052d11ec04c00f5b70c1db0eaee679d515437372a4beacae7447c7f43332d6010ff69b2f2284b9aa64ba81463b8e0c2a9b8c635d648972dc8d5bda536e785055a228feb90e130bcbae98b961e993284222702864ff6676abe8b904a1458628373c29cb9f50abf1d84692f6315d9468534416d9fb78e4463d1b765fc5952c06a69d3e9249d8c52e0503bd5e8846b5fba8cad43d53638d5cb2b3a267cefcd0649fa4cf043872e05781dbdb67b5e4845d881d3a27244ce80757b53181909b99a5a07d29b81b92300566c9f7275f3df50863d3223f1950155968156b4f89c55fa2513cffe5007823093d1b1ef1b61428681f5aeb5d5343b583a6463a72350f2258d085c5b2c7b1d0d4863c378d58b9370d27b90860466cc578652910028774b0108fec29c12022c926aaabf422a76407997572b6f04a4f3cb6b44d3349f022c52cc79e835848f79a4b624caddee46677f98b01da4ea64778042763856b8a1bebabe28b96bcb90058f10a12c9669f083c84e7a22ad1aab9e100dd65779c80417422c0c9495f3ad27fee836fd34bb861234be6d5977195a66b13197f9370c983870f62356bc640385070672689d178258ac9585d0baa02b38d55075b3f76360cf4c7c3430178a0a204732f72f639d6820eac408015c43a9bbcb7af3454bd8a4362264b9fa62c97d23781384e02f660a35bb2b28142f99bb4af6b39fc4ba76e168685441432d03d1c688406b5941dcc3c08a361b0a12e0a4ba2996a9795753478b5051d23301ea959defc0995dc5ccbe90ade9195f798625c4c3582e350e1567df0805bc662aff3a69e4bf3051d3b4088216e43782e556179099611a237cf1c688a86b0078c37843101b4c3d536d9971e8b7656209026e0571c78abb1fe3420b1b1a6efb16e4e7730c289a1e18b4ee9d09a34aa007e626586b36f7f990608c43715158f56b88a6c401b663801ca86a34af365b615c21a7a6fe3a30295b1091c2c80a8a10c7b766da4aa9eae206a1ee7ab4f0b5f646562e977b232e14e6d320255f6c0ea332b7851039dacc78490a8a2f83f9f98ac0e231137d48d38f1395d115097dc8ca6ba416c4933c35bbe17196584f176f05aa113e88af077c144928aa3c54f56e692221c97b6485aff043b7d3660702c84230c2ce9070df0ea0d84ab05acb664ba07033246bcdd13ab3aa0becdd23424c43d4bdb8e9fa5c611318645123d84d273134894699b0627f1afa31705496298287007f132939bd06478e48a8ac339ccb52373547a4250c429880f5fa09c739221a360768d9668380368f6924590a89373e158210a061f8884b7aa3cff2c0d187a20f2ac4d54da6999204744c29ee2b6108798ab11493828027caf2954b718a1e9470e7595ad0e842218c4640442c6ed991df374b1823680da19b29aba5a242531d2f17043b834d3392b8ce8a6bd9815060696f5a5aa7c51603c537470e17533747e33261809671665c3b169dc67e4aa243f1b30a2848b3a465f463417e6a0ac0e157ac4971c396518b64accffd1689c635d63bba8fda97be6c4a77b86000c3c86604a293c9b29e3e6106915773368b7049a6eec5776c436afcd2679d4064fe73cc06b5ba2ea84007028b3f782569d03c698b72c48a378fa9ad51e90797f7c42b4fd36cabf922d5d183ec9d023bff783a98ab2c2fdd7ecbec4d78b849e86db163239e49577f28caea4f815b2c91e20e591c0580c8b1219001d0020bec4d78b849e86db163239e49577f28caea4f815b2c91e20e591c0580c8b121900170041047c37d6980423043f9a7cd9c3031cc29ad85a1f400513548408b97120100f6c325b6639712f15662407b0bbbc30bc9b2c2880c552de246382d8286ecdec22b524002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001b000706000100020003fe0d02390000010001020020818e96714cc481c796f279e613f885f6c0d031af210b18f1f184b6c1f8cf42c4020f663a7ebc5da0bf21861a452f6d328326323d3ea5f23b8e10eb9c919b5157d2be0c50a5a763b4e7679c806ba68855be8bd737090fd822dd8db47ea9b88990c8ce848fe6c69a2957788c7d01effff3a2237a47835b75b3061f8f4150877cb9c0f0f755fa7cf96a6d37486c0b8af92287b920fdfe14e2fe33013097992f45a17c495eaa9f3cae1650f488d8193f29507d1cec577393c9a8ecc3f3787885b7f1e02f6e8f976a4aee2be93a309b0f6f57c14b2f549403aeaa649cb5a93ae7b2ff4a1f6a72379e0f45592c76a5f09f14b522307455aed046a809745235f0c3aea27f4115395506a0f93e9326fa996351ab58e58fdb18b92d40e6ab6735bd2e8fa2149080bd770a6c7ab383615b3283ef607090c10c2cb2361de69be65e15ee7b211085e649c75fe05c8353a205a6af2ac95627d12d185b4f6af03e68c2b29996600e55e26027c32b626c2555c4a6b92cc1c1f86acd2fa633079fc5286407c3c47af2dbc07e13c3786ffdc4a2cf71767f78152bbeb396018400735ab795935dfca83dca7d04a03eb4dc97a5d3d14a411b3c08da3791a40f16c74c6f4f4ef5a5eff2c7a91ef2d693137bf3fc961ab5be08ac849eeb0d2db18a310061cf31d9a355f1d7fa50aee68d3dc18fe4ce9d8edd71fb78aede3320716d57d37a2eab304ba73ba8318405356ccdf3bd5c379e1fbd4a7daba388adcd95795e82c6f5d0d201758aa4a5727584d92bd91610e8c7133e996cb10029010b00e600e0dc79959a1b80840503d9d542d170081f174e6454332b372f880d0dc42eac42d340accc5f7004bfc65db7a9dcd83a246d2888f9946e8601d453a784ca53eff73aeadfe3d0a79c3afb274f40b973de59edd48d4563b9b9205b406b138b24fd29ec844aae8df49974820d2e036552dc8a13497378db514c2f807440c31cf7cb033b2a57077b533539a3a31a100d22b4786e833f178383882119d79943141b47dd3a5a17a87f2415a24a9123206bdc938d917c8a6ba86d5ee961fb1704477aba9b0f38edff7573a5ee7409de95665281d3f263f39de2f48846d8497dd8e9f8a8ed823039523900212012289d3ec9f11f84fc928eaa749c11961872f395478fd189d70bb86a2085dddb";
const char* JA4_r_2 = "t13d1716h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201";
const char* JA4_2 = "t13d1716h2_5b57614c22b0_bdfeeec9ffef";

const std::string raw_str_3 = "010001fc0303e4422635180a6d52305577414519930d2eb4b714ecbaffc7aa4ef762421df37920a89626d7567923c523a5255cfc150232e8491a92f4d85e848d5f8432baf6d273003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000001c001a00001772656d6f74652e7069786965647573742e6f6e6c696e65000b000403000102000a000c000a001d0017001e0019001800230000001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020d8a1f885af25dd99f2c6a123fae44fadc43bc5d9c123e0ec0fbbdc0a90a6b24e001500c20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const char* JA4_r_3 = "t13d311200_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,00ff,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0015,0016,0017,0023,002b,002d,0031,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602";
const char* JA4_3 = "t13d311200_e8f1e7e78f70_d339722ba4af";

// ServerHello samples

const std::string raw_sh_str_1 = "0200007603037c0ed417717dfe498249e3705256efdef042869207bfe737e932090361814f4a205218d9ca4347e1542abba88727e5b2d3d2111127ff330b028ed4e2530103a8f4130200002e002b0002030400330024001d00206737ae5fede31b3aa117a98d74ef592a40f8f5dcb703844efa38f2561e735a0c";
const char* JA4S_r_1 = "t130200_1302_002b,0033";
const char* JA4S_1 = "t130200_1302_a56c5b993250";

struct Samples {
    using sample = std::tuple<std::string, std::string, std::string>;
    std::vector<sample> samples;

    static inline bool DEBUG = true;

    void test_one(sample const& s) const {
        try {
            TLSClientHello my_client_hello;
            std::vector<uint8_t> client_hello_buffer = sx::ja4::util::hex_string_to_bytes(std::get<0>(s));
            my_client_hello.from_buffer(client_hello_buffer);
            auto my_ja4_r = my_client_hello.ja4_raw();
            auto my_ja4 = my_client_hello.ja4();

            if(DEBUG) {
                std::cout << "DEBUG: -------- \n";
                std::cout << "DEBUG:     MY JA4 raw: " << my_ja4_r << std::endl;
                std::cout << "DEBUG: SHOULD JA4 raw: " << std::get<1>(s) << std::endl;
                std::cout << "DEBUG:         MY JA4: " << my_ja4 << std::endl;
                std::cout << "DEBUG:     SHOULD JA4: " << std::get<2>(s) << std::endl;
                std::cout << "DEBUG: -------- \n";
            }
            if(my_ja4 == std::get<2>(s)) {
                std::cout << my_ja4  << " => CORRECT\n";
            } else {
                std::cout << my_ja4 << "\n != \n" << std::get<2>(s) << " => INCORRECT\n";
                throw std::runtime_error("incorrect fingerprint");
            }

        } catch (const std::exception &e) {
            std::cerr << "Exception: " << e.what() << std::endl;
        }
    }

    void test_all() const {
        size_t i = 0;
        for(auto const& s: samples) {
            std::cout << "[+] --- sample " << i << " --- \n";
            test_one(s);
            ++i;
        }
    }

    void test_random(int count=100) const {
        std::vector<uint8_t> data;
        data.resize(2048);

        for (int i = 0; i < count; ++i) {
            RAND_bytes((unsigned char*)data.data(), data.size());

            TLSClientHello ch;
            ch.from_buffer(data);
            std::cout << "Sample " << count - i << ": " << ch.ja4() << "\n";
        }
    }

    template<class JA4like>
    void test_random_base(std::vector<uint8_t> const& original, size_t mem_start, size_t mem_sz, int count=100) const {

        if(mem_start > original.size()) return;

        for (int i = 0; i < count; ++i) {
            size_t start = mem_start;
            auto chunk_sz = std::min(mem_sz, original.size() - mem_start);


            std::vector<uint8_t> orig_copy(original);

            RAND_bytes(orig_copy.data() + start, static_cast<int>(chunk_sz));

            JA4like ch;
            auto ret = ch.from_buffer(orig_copy);
            bool parse_ok = ( ret == 0);

            std::cout << "Sample " << count - i << " garbage spot(" << start << "," << chunk_sz << ")" << ": "
                      << (parse_ok ? ch.ja4() : "cannot parse ") << ret << "\n";
        }
    }
};

TEST(JA4_CH, samples) {

    auto s = Samples();
    s.samples.emplace_back(raw_str_1, JA4_r_1, JA4_1);
    s.samples.emplace_back(raw_str_2, JA4_r_2, JA4_2);
    s.samples.emplace_back(raw_str_3, JA4_r_3, JA4_3);

    s.test_all();
}

TEST(JA4_CH, random_buffers) {
    auto s = Samples();
    s.test_random(2006500);
}

TEST(JA4_CH, sample1_fuzzing) {
    auto s = Samples();

    for (int i = 3; i < 350; ) {
        // original, start index, random length, iterations
        s.test_random_base<TLSClientHello>(util::hex_string_to_bytes(raw_str_1), i, 1, 6000);
        i += 1;
    }

    for (int i = 3; i < 350; ) {
        // original, start index, random length, iterations
        s.test_random_base<TLSClientHello>(util::hex_string_to_bytes(raw_str_1), i, 2, 12000);
        i += 2;
    }

    for (int i = 3; i < 350; ) {
        // original, start index, random length, iterations
        s.test_random_base<TLSClientHello>(util::hex_string_to_bytes(raw_str_1), i, 8, 36000);
        i += 8;
    }
}

TEST(JA4_SH, sample1) {
    TLSServerHello sh;
    std::vector<uint8_t> data = sx::ja4::util::hex_string_to_bytes(raw_sh_str_1);
    sh.from_buffer(data);
    auto my_ja4s = sh.ja4();
    std::cout << my_ja4s;
    if(my_ja4s == JA4S_1) {
        std::cout << " => CORRECT\n";
    }
    else {
        std::cout << " => INCORRECT\n";
    }
    ASSERT_TRUE(my_ja4s == JA4S_1);
}

TEST(JA4_SH, sample1_fuzzing) {
    Samples s;

    for (int i = 3; i < 350; ) {
        // original, start index, random length, iterations
        s.test_random_base<TLSServerHello>(util::hex_string_to_bytes(raw_sh_str_1), i, 1, 6000);
        i += 1;
    }

    for (int i = 3; i < 350; ) {
        // original, start index, random length, iterations
        s.test_random_base<TLSServerHello>(util::hex_string_to_bytes(raw_sh_str_1), i, 8, 36000);
        i += 8;
    }
}