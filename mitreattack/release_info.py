"""SHA256 hashes of all ATT&CK releases."""

import hashlib
from typing import Optional

from loguru import logger

# This file contains SHA256 hashes for officially released ATT&CK versions
# download_string = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{release}/{domain}-attack/{domain}-attack.json"

LATEST_VERSION = "17.1"

STIX20 = {
    "enterprise": {
        "3.0": "d8e450a8a06e62621ac621616d8c01df9872b57b50577f1832bfc473594d73e7",
        "4.0": "a4ba01e3f9287aec6cfd8dbc48c374d98e9aaa4185eb3627595fbac62ad57602",
        "5.0": "be5506a4c02b6af99b76fd615306394ae83b48108afe0dbdb45e35bbdf8c7352",
        "5.1": "1531ebba8d473c9eff1c83980c5066407ac50e228e8d3f543547b9454a0b0871",
        "5.2": "6a2d54d095d7ddb39051d65cde79f86c0cc2c1439081e1d401083134df926296",
        "6.0": "91085011f0e6169f392cd8397883cef2c28d24fecf77893c9a75263223ea7f77",
        "6.1": "27a9cae7a0de3156dcc4c27a958255fbe769ea1f0b28410ab55249a9167aa5d9",
        "6.2": "2e78904627246e94fa8bd1aff661cd4912efb82370c5b2bb32848a435f44353b",
        "6.3": "c7b416f938e5bbfbc99832bb544b63197b6f1fbd4a3186f7571fb5be646f3917",
        "7.0": "83fe3d29303162c39b94a552eb5d6828c5d490a8ebd694c61279c04d024a2a17",
        "7.1": "110e2f8f0fbe2e85d2e20e1b3e87019222dd1a42e19927d0f02979b00fcbd5e5",
        "7.2": "a78392d56a4af4ca156feb4cf65199fbc2d47d3f7986d17872347b504f966ba5",
        "8.0": "d8e45541cb1d1963801e7dd4f2fe3ea098139bd11bb268cb6176fa1b9d106832",
        "8.1": "5ea4dc64376ad43141c1290ff0861fd2c649c7abdd9c6675e2fbb974fa7ccddf",
        "8.2": "98a96ae0b36e9cd99048f16da28ec177b9b50249111677f0a194013f50f70366",
        "9.0": "3b084e1b504fc18dcf72f8a930e3d276eef1395bae255b4fd0c8e4b9b286bc52",
        "10.0": "a8556cd1d01a77f117d09d313ba7006d77de0bb3dbe34395bc83e9d2eb246d00",
        "10.1": "e7227e11122f4b82fea3c0f8a72bb9e6c6e34304b5d4bc90c020beb0190aaf74",
        "11.0": "e31694f24943a2de438426f8a8f5abf969797c7819cbb80bcbe83c8432826e2f",
        "11.1": "604da64770e0ff025a9a164f4568f4e56e9eed2038292510574648f6b8edae6a",
        "11.2": "5308b90f31df02310065ec5daed9099b3d2bed45c58e6c0c7ce84370e7552f6e",
        "11.3": "5308b90f31df02310065ec5daed9099b3d2bed45c58e6c0c7ce84370e7552f6e",
        "12.0": "a8952b72ec4104c959d0ad642541dab1b84d835f439a77f7d1322d794aeb4aaf",
        "12.1": "f4d709b097b1b4b812d2d529e0b3851cfe785653eec42c9294501078f6d246df",
        "13.0": "643846c3be58937bebeb280a69ac919b9fac0787ed16bfd3250be9a25bfc53bc",
        "13.1": "02f3755e4260c81318b1dfdca57451228f7a09c9beff9839ed67e24327ea3933",
        "14.0": "baed21374854d38ea2276e04efe2dd2e6da2d73c85d14f9b8bd2c3f77cfd7289",
        "14.1": "d32bbadf099955c965d057dbf4208ebefd31f15f46aceffc6673994192051202",
        "15.0": "7318ac9cd5f91d88964bca52e29e1980fb36f431615d723e0ffc893efa584323",
        "15.1": "39b1f158c2e1c604801da2f75b2be9e6a448a7250d69db628168a0f7be056349",
        "16.0": "b7dc5c7660ae2e8e6134497c705a558a84bb9b614545ddcf6f8e278eb741a90f",
        "16.1": "2ac69e84c4366af274cdff2c406755c781c1865e1e847ae16207d621a2fce5de",
        "17.0": "9529a98db3358a4132304590d914a28d80f4a03aba5656685e3d0ed43123b888",
        "17.1": "9537a22166367a5b3c1434f5b17b27361cb9c88b34926e655344768fdbda3e85",
    },
    "mobile": {
        "3.0": "1385d94348054c1c1f7cdc652f0719db353b60c923949b10cbf8a2e815a86eb3",
        "4.0": "0962006ec05389235fd12a86e53e4e2160f05e278e5371f197a125119bfa92e0",
        "5.0": "f7033c1508877dcb9d99cf62b02d0cb66a1f37711f06ffb4040ee38c4e352fdf",
        "5.1": "f7033c1508877dcb9d99cf62b02d0cb66a1f37711f06ffb4040ee38c4e352fdf",
        "5.2": "f7033c1508877dcb9d99cf62b02d0cb66a1f37711f06ffb4040ee38c4e352fdf",
        "6.0": "b8b97f5f630b0254c9266ddcc2ba55aec6ab4aff39941bae17b9660c711e9473",
        "6.1": "b8b97f5f630b0254c9266ddcc2ba55aec6ab4aff39941bae17b9660c711e9473",
        "6.2": "b8b97f5f630b0254c9266ddcc2ba55aec6ab4aff39941bae17b9660c711e9473",
        "6.3": "32bfd628d29b8767edf3d2d60e048350a9670d0a86781384cc55c50080f0f144",
        "7.0": "19e0053761ca5db191259a2606600e04d7ae81f4da948a956d77150edc61c7ff",
        "7.1": "55bbf98e5f0ce89fbd33ce3722a15a513cbce1ad48188571b20ea77ee66cb6f8",
        "7.2": "6cbced5ebb42299f8ff3427d60b2e17c3b5e9c2b6cd021f25b03e9daecf84929",
        "8.0": "2521c3bda599737ba8722c36d195c83ee3f1d8babc239cecf792994cc205665c",
        "8.1": "2521c3bda599737ba8722c36d195c83ee3f1d8babc239cecf792994cc205665c",
        "8.2": "2521c3bda599737ba8722c36d195c83ee3f1d8babc239cecf792994cc205665c",
        "9.0": "cc169410e264b9c05a8b2a1ab2a76875d66496aea566b0c18436ea3165f8f456",
        "10.0": "b555b6b3fc5ea8fdaa65f7a97ba691d7d7e0aa3e3dadd2062655299d8d302259",
        "10.1": "2b1e7cbe1e10a1e86ac3e0c97f7e6e03345c20fee3baddab47a9cf36a438bb34",
        "11.0-mobile-beta": "0cbb728a1ec9b36bc9bd8072ee84b642949ae8f46c0bcdf95d02e7e322b4c1b9",
        "11.0": "2b1e7cbe1e10a1e86ac3e0c97f7e6e03345c20fee3baddab47a9cf36a438bb34",
        "11.1-mobile-beta": "f08cd2fd0a73b4a028b26256304a4b1f81bebc37271e3612e946114ff0f43b85",
        "11.1": "2b1e7cbe1e10a1e86ac3e0c97f7e6e03345c20fee3baddab47a9cf36a438bb34",
        "11.2-mobile-beta": "6392db7b2a78cc14e5ade2ece4929353bc55d9f36388166ef8d59e710af9ca74",
        "11.2": "2b1e7cbe1e10a1e86ac3e0c97f7e6e03345c20fee3baddab47a9cf36a438bb34",
        "11.3": "2f9464419277e3b7d59dc63e7662219876ade75380f585ffbfa9ddbb9a7a2e1a",
        "12.0": "968d3bd65d1056575112dac49d415017b88d1954bf4c2cdaae3e87bdf10d23b1",
        "12.1": "ec6b8b068a47f2b3c93304857d4306d0baa0bc7252c46c2e491768dd51682518",
        "13.0": "fdea483e1ecdf8973b3fdda08baaa6044954732e5c1833f24625ea44f5ba2952",
        "13.1": "5e953c2406ce566929290074685d218c58844411906bb743ac35023a66650d12",
        "14.0": "fbd778271946f8e498924c8e6a028a4b6dfa6fc09cd725cfeb2e2cb1506619b3",
        "14.1": "a3256e636004de45e47a1ec5d971ecc7de3e4d7c3d7859bcd4ba71bf4fe3c408",
        "15.0": "0cd1d7171dd5d5a9f6ce52d27e3e28910bdefa76cc95fb309ccbe3577479e0c9",
        "15.1": "9aaafb3b351941d35a38b02baa8ac175ff6c0ecf95eea91b6fa53de9db32432b",
        "16.0": "d1e36df775dd7fc9969c8b3a8432b6f251883c66a7b9657b7a67013c83f2fa45",
        "16.1": "4a8b58e2bce7356ba29328a4eafc3e19a19a0bc2c726c8d9efe8dbcf2781931a",
        "17.0": "28acb21b650309688c3a5fce6da3185a7ba934582853ec13fcc3c8f3753b1188",
        "17.1": "736078773f05ee943c0aa71bf71b935b04315c134809e8b678bd45c89cb1ab49",
    },
    "ics": {
        "8.0": "2e9e9d0d9f0e5d14f64cf2788f46a1a4403bc88ab6ddd419cfcdfe617b0c920d",
        "8.1": "de89e2655fbd759a4aadb62858ea0fe9371144ef9030296597cc85d5daa3a3ee",
        "8.2": "0cdb0d6d63f9a61259529cc6a78ad02869824f1e50c480f2ff0a26a4c5758fec",
        "9.0": "fda075f44abb25442b3cf41c8333d9ec1f72edc014adeef730f3289ec34b0c69",
        "10.0": "c79483dc347081f8aa33bee1c8c82916cc14febf87601d7035291bf7a213714a",
        "10.1": "faaf4766839d64edfb42db27e6023dd9ddee6e93d66495d8085ea9a29323cb1d",
        "11.0": "5f3f6f3fc2359daeb6b7dcb712f5fef6e0af1b6628e3881f087b2300f3b80f67",
        "11.1": "615250d6f1cf6f96ea7a0008432ffe35f548035c0b129ad464336f060d95f490",
        "11.2": "27acf3feedc6f691628d518e24a8bab60ced4a95ed4aa981f1945299d2756913",
        "11.3": "1fdc37038d2f062226685cd9d54923816653d15aaeac779c1cf1881b3f451a28",
        "12.0": "557e1db96541cfc4760a34c6a926805f9faddbeade21aa2b2e56c5510d46ccd2",
        "12.1": "9d71771cb218c76e16a53c1046388758cd11125f9cafc1337a33a6f3a6ba62df",
        "13.0": "37f9e476af404788f40ab059c347916003117b64813f29586701d42c427fd3aa",
        "13.1": "f00998aa9f28afa9a3658296bc9b828931a1da2632e3573cd6be9d08e20edd8f",
        "14.0": "a08b2e49d523432cb02bf947bcc14d24e6cb9f8c6e85fd6b1ae90dc896a99573",
        "14.1": "0d165877c1d35675d05d981877d5dce7ac6921eaf7a8aa81427ab15d12b02ea8",
        "15.0": "79d0d3d3e382431b1ce7dd2d256936101c91daf2a083505e9f8f4df100d3b681",
        "15.1": "5afe7fa3cabbae4686ce034b196d2a82ec8667ec86fee1d6fb58a7fb9eaeb857",
        "16.0": "53292f68d4fe527336d7fcc28ffb8d6a19a2ae94c545716c7791d147e3c7015b",
        "16.1": "353ef4bc11f0047f9b06ce96253e81c33d265e6887ac8618b0625c648d58f470",
        "17.0": "79695ab42a22e835aa85c610fa2d0e0df97ef80238b36c5491b5844b81749ab1",
        "17.1": "f0bd44fa2e167f2e9e94700f9081571dfedc49bebd856ea0d7ec24cf896d298b",
    },
    "pre": {
        "3.0": "bc59c1b1398a133cf0adb98e4e28396fdb6a5a2e2353cecb1783c425f066fc94",
        "4.0": "3ea1386fd458ede067cc5134490eec04a266c7f374ec4b343c3973bdf65b1900",
        "5.0": "1dd68e2b4c0101bd4f07cbad8aa48978fd379b661eee36c23b626e2690b306ab",
        "5.1": "1dd68e2b4c0101bd4f07cbad8aa48978fd379b661eee36c23b626e2690b306ab",
        "5.2": "1dd68e2b4c0101bd4f07cbad8aa48978fd379b661eee36c23b626e2690b306ab",
        "6.0": "97152ddb198018dd7f67be438cef2955bc645529da8cebf9db77c8cfc5172f2b",
        "6.1": "97152ddb198018dd7f67be438cef2955bc645529da8cebf9db77c8cfc5172f2b",
        "6.2": "97152ddb198018dd7f67be438cef2955bc645529da8cebf9db77c8cfc5172f2b",
        "6.3": "f1072190c89a2b3b3a7fe9fe9063f49b678f8099652b5ed70b367f34f37d9c50",
        "7.0": "3d7c1e714b4c3645b255153da023d99e1e57e44b7945a5a63b26a7799e0f7dab",
        "7.1": "e3991e9e09c10908daec72d7efdccf079f2b98924b5c04fd2fcd0c21ff09996d",
        "7.2": "e27306d4e8fccc552abb4f124b011d87593b394e31e48f153e3c580d5e824799",
    },
}

STIX21 = {
    "enterprise": {
        "1.0": "72ffe9d2b643355ea96353226e62c511f3e242d43833237efb208f73518cc98c",
        "2.0": "85ce93d153ee41a93b8709b0d0adc3d1b6cd45a4b5c54c6ab43733165f5a28f5",
        "3.0": "aae9f90cf5ebb98411459a234ccd9e0f695c7cf3252848b92c81dfe2c4586f62",
        "4.0": "8ee1a5fa97d9e14d38d00e94d5b1da9bb0fb04839e500cf4e05d348d25ed10ca",
        "5.0": "50242530899c83c4f9a4e55200ae21cc12d87d05fb5f84de87b5de9319dc9e02",
        "5.1": "70c0bd0c2cde0ab614195f7cf1d497ccd960ec04a176520a1437fd36289509e5",
        "5.2": "29f07e21808a4f20f031a14afb60a09949c5eb485eac25d2735b9e2852685191",
        "6.0": "3afa4c51ea01e5f45eba0ce7a83684825e45ca13fd57d754d083996e4902b72b",
        "6.1": "b0f163a39ae1cf6dd5b6ba2ebb2d7153305f0535db32ca1311df5c2c95398b98",
        "6.2": "c79aede43b84913e47b420b267eb76a55f05c3ead591679dd66a0544da9579a0",
        "6.3": "91a073f92d1f814385d0acf4b403d36965c0cb7613b1188e2995c8d27d170752",
        "7.0": "4976b601e77b5ed54607a78121fbbdb0949748259dce6712dbdc93fbe46ef612",
        "7.1": "d24dfe9684db1cafebb1cbe17075a2660251c426a0e2c62048603b816f51d4de",
        "7.2": "04728e4b995ee7e2d6459fa91716607ac53d254d23d4dc10ed7e2d85a9046e00",
        "8.0": "0323f274d39566d8bb5226daafd0c733a00c3d6734bf041dcb29e2758af8f666",
        "8.1": "abdabdfb0ea6b6f2e466762024efab26c8b4cfbf57a261d6f26bb1a42844cc70",
        "8.2": "8af8ba82d52c2735b1ae6804ab4f2cb8812121d8cdc37e5523ffba671d9ea69b",
        "9.0": "a41aea2db10ec3839a288947813f87a4fe5008992abc687c5e7072735ac0a5b5",
        "10.0": "2f94b071ce34a9e0ff84b9f6e8eec69bef78b1e44ddd2153abcb108af377e5dc",
        "10.1": "0a999035f26f4326ad670ec51727014fd42c21fca4bda4be784ac6ad0510fcb6",
        "11.0": "21e9b07b0357c37ba3276b38ab6a238946a7227af95008846304788103352977",
        "11.1": "55b988ef92577065588e0bddc96cc888c255dcdcfe3a16cdc0b6124518f5a37b",
        "11.2": "0f3b83d5c165feae559793af801dcfd3ec819723622d59eebd5c48d292047f77",
        "11.3": "4bb7a2bc26246e029f2cb722e5fc8637571322e33e920b1d2337921b2be8e688",
        "12.0": "72a51e3ed0acada804652231e790554f63ed7a33957da45b61f126b379e75812",
        "12.1": "e84679af4bc46bba2ba92f60182101f146d5b966898e47924de7321e6bffeaa1",
        "13.0": "06d1b1196cf8b4d5b570ac19b0b41da66769aa1827935cf8be8bbc199f5ba6f6",
        "13.1": "5ec90131dc595ef7f2dd6ae0ee24074fbd5e317ed3261f9465660e04f97d426d",
        "14.0": "87d503af611d2545f62224ef65e90b07e14935176b88d407a6574f38676353cd",
        "14.1": "13af7514ad1bcb59deba6b6b46571168544bbe674eb52f41361916bb1cd9c3d6",
        "15.0": "f327d6bfac80e09db35fdabb2e92ccaecffb8c370f59555dbbaadaf930323cc0",
        "15.1": "a57988bffe402bb3e19d92dbe80a12143e1970b814e013e080f9df2fa5a3f6bc",
        "16.0": "b7c3d0bc3ba895a95bd79a8a441362a74388aebee16a223e4421d72bfb2922d0",
        "16.1": "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813",
        "17.0": "c8966a9a55f1723c0082910f4522af448514343f84ffb9a3e757bdd59642d057",
        "17.1": "0d1c347a4d584cf7e11ef46556c33b7689341443bf86299188d46c307274323b",
    },
    "mobile": {
        "1.0": "7da1903596bb69ef75a3c2a6c79e80328657bfed9226b2ed400ca18c88e0c1ea",
        "2.0": "e97b49ceb7859f3612fd28678e7e85a0283e3c108c655eabd28a515587434cef",
        "3.0": "22a587a97f7fd10a598ab91f36e3efabbf58789914d174a167235ded2255c25d",
        "4.0": "4961c2193209ed3b2f7f6a4df451a3fe99b99bbf674ff82ec715afe826daffec",
        "5.0": "c53f29572621ea39d283581f55da420e34aef2003b3539f5706b020febaf973a",
        "5.1": "f02fbf93104037b3bb29fe131aa78abe2a8abecd58ea3fe0beca1a85257fc453",
        "5.2": "f0f1e07a442a7fd524275b09082baccfdaa30741109136361b69ff4fecf98ee2",
        "6.0": "6ca6aa63cafa06e1386186f75135de7de3eb4e049fce8c3c642f97ce7c7d7f5e",
        "6.1": "4a5a439bd04170625c17104930bbdfd5b18eb4fc005938908ac572561d2f30a7",
        "6.2": "b1ac6537582707c23d806e749408458649b02b6832ce16240c0db0dbb5ea8734",
        "6.3": "299cfbcbdefdf775d6aa9be2114fb0b6999762638087e315249eb2d867592066",
        "7.0": "d29b522c1b9d86b6ea3af9a7b0b70127b0e343fe28f33d6546c93f5137e93c3a",
        "7.1": "03471c385cc988979a2dabff8d7e6b16a82d0c584bc583dc86ddf89179776f68",
        "7.2": "edc0291a6b2f0a550ec1cd873915dcdf975fbd27f2c410472d326c24cae51d21",
        "8.0": "efdeb44382fcbdb82cc464512900e4a97bf520f7c142c40645790a4cd02cceb3",
        "8.1": "bd28dfef9af8bc654987d53eeaf84a6cea49abbbe8999640a434d6196083c049",
        "8.2": "d98c86fd8f86d23ac7d254ab1ec11ef8b2382d8b32a1125d1c8057a2e942497a",
        "9.0": "ca532d3ff56e64f6b00f49d4bf561902de06c3db733b769c50fef0ebfa543c40",
        "10.0": "c6b81d781ba15acc556d2059974b18d8c7597c330eb3b60c03860155068ba70d",
        "10.1": "4b2832615133cee3c339319a7a5cf02a402ab17de399264f2b879736eeadf91a",
        "11.0-beta": "fa266361b3cb12d8cf25efbf761f4375eac58e4fd9c94756024ccce9fabfda99",
        "11.1-beta": "fe2acd79f9808331fef5d9c20344bd926983b507554218ce4a8d2f015919788b",
        "11.2-beta": "09b2ca5c5dc27c95eab38dbf02e024278e2c3eac59106921ae773a0e46df342c",
        "11.3": "d9a4c07fd7683d6f8b6381fdbd91be14f56744922c65b506eb135a5117446b4a",
        "12.0": "04fd1402798911c3aba0915555e6477ef2c4d398f5b0066c596456c1916bda57",
        "12.1": "523df967a16af830d10f10147c65119824028b912d8e9d7df0242278f0ec3869",
        "13.0": "b2c56eccdb9914169f07fc2f41a6b40b2af9996e815682883fa2c3c6fabcc2bb",
        "13.1": "b5aee04a15cdfcb070a89d06972f94bf059bbe23c028993fe1953388c777b44c",
        "14.0": "4b2f63e2fd127f6977796047ba3fa96278024553f9195acb34782e6838f37a7d",
        "14.1": "3b861ccf2e884fd69a947d4ba9b4b9ab019fcd29d4b49f25c8e22960cebc71af",
        "15.0": "4345a378e16648b35f0777fb1b0a83cfacbcdf4e5fc555d6f415ef50ef135a0b",
        "15.1": "96d498a5c913ff679eefda17b1f0d30d0351bd5f68ba41d1b02b66e5146a5738",
        "16.0": "ddea27149eddebb4e77c6ebb4e2fd2f92c71ef8627bbf7610c37e055a2adb7fd",
        "16.1": "f84d5bb908c918aadf6cfbdfe0e801fce354e943d999c684b01eefa81da95941",
        "17.0": "932287bfd5e708f836fa1115d2b776934ad490d5fe94b3b4e25a140f0f636fd2",
        "17.1": "33968697b94a5ff5568016a28bbcc93f7869dc2f2b2653ead833758867ab5bc9",
    },
    "ics": {
        "8.0": "f3b53ff8d7f0f21f3e48c651edf68353aeb3e07727c32c3e47ef882e3bca10ab",
        "8.1": "9f99fe291a49d0de98663edb6056fa7f01cdec4dc39f2d4fe5eff40265310da6",
        "8.2": "cc69985f589053f5a5e96596e8649ea770afc09a7fbcdd2febc470a6d596a512",
        "9.0": "8aa6946124a5ee58680894634b2314dac06381e68998ebadd89626b4a5b7e30e",
        "10.0": "bb05f1bfbc1ae41831fb6eca50860a638b00561923091625ebdfeb8cb31eab29",
        "10.1": "4717109449fa9bb6fc07d64f983add52c893c6ffff3ae6282ee7bca9a3ffedbc",
        "11.0": "8602d70ec24ea927cd38d6fa72afd6035d36ca38238af28ca0056ed7eeeb550e",
        "11.1": "06335a9437d6acca88dbd5a127450f043184b5fd7d243a997e161c3bfc1a9b02",
        "11.2": "156e36c34ad8869276320d69f924978941503f950942bcfed5a6c5d5bb638f81",
        "11.3": "31c0901b94faabc989655457aa4a000007fa6441b2208b10f013b0a2c5ffedec",
        "12.0": "aaf7192b780e29d9be40967333ed085d451fa1bae797e51989abf636a0eecc75",
        "12.1": "a972bb296cb12c2fdb9f27ebdc3d78e399453aee9c69111cf9e8b4269f2c6d09",
        "13.0": "1349d7dae32393cbec5a8accf6d894df2ccfb1be925bda646745a0b1bde31e65",
        "13.1": "a38dc91436b620792789a7e3b6774b938ee25512afca30aeae336cb6f6c16c9a",
        "14.0": "af632a34542dfe2b14eb00995ab3240ab963caeea420337255bc7211b9e17a07",
        "14.1": "580c7d8638fa01cefc155efba96aced80190179b9cdae0eaa0490a57571f186a",
        "15.0": "854ae8f06400d677b3d1a3bb4675f9aec8b8863726d77b0211164fc96814d6a9",
        "15.1": "a995c65a1ae068a4c26d1c37281b298a107d61ff0b84e57c538f07f4c4bf55e8",
        "16.0": "65a41a855c4b84ae693d2ef96fbb1e4860f496224e68a1a2448f0e2463b4a6d4",
        "16.1": "86204d062732edf593d3736fef0b302832b5a8c601f21ff446c76f23779ea2b3",
        "17.0": "e16dbcb5de0d7a79d9550d690e850841f266e8cdabc0f3c8da8331232c50612b",
        "17.1": "cb207f963ca270994d9dabefe52237d46cf25056f154057f4b961f1c0803a8f3",
    },
}


def get_attack_version(
    domain: str, stix_version: str = "2.0", stix_file: str = None, stix_content: bytes = None
) -> Optional[str]:
    """Determine the version of ATT&CK based on either a file or contents of a file.

    Parameters
    ----------
    domain : str
        ATT&CK domain [enterprise-attack | mobile-attack | ics-attack | pre-attack]
    stix_version : str, optional
        Version of STIX to check, by default "2.0"
    stix_file : str, optional
        Path to an ATT&CK release STIX file (use this or stix_content), by default None
    stix_content : bytes, optional
        Contents of an ATT&CK release STIX file (use this or stix_file), by default None

    Returns
    -------
    Optional[str]
        _description_
    """
    if domain not in [
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
        "pre-attack",
    ]:
        logger.error(
            "domain must be one of [enterprise-attack | mobile-attack | ics-attack | pre-attack] to determine version"
        )
        return None
    sha256_hash = hashlib.sha256()

    if stix_file:
        with open(stix_file, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    elif stix_content:
        sha256_hash.update(stix_content)

    sha256_hash = sha256_hash.hexdigest()

    if stix_version == "2.0":
        stix_hash_data = STIX20
    elif stix_version == "2.1":
        stix_hash_data = STIX21

    releases = {}
    if domain == "enterprise-attack":
        releases = stix_hash_data["enterprise"]
    elif domain == "mobile-attack":
        releases = stix_hash_data["mobile"]
    elif domain == "ics-attack":
        releases = stix_hash_data["ics"]
    elif domain == "pre-attack":
        if stix_version == "2.0":
            releases = stix_hash_data["pre"]

    for attack_release, hash in releases.items():
        if sha256_hash == hash:
            return attack_release

    if stix_file:
        logger.warning(f"Unknown ATT&CK version for file: {stix_file}")
    else:
        logger.warning("Unknown ATT&CK version")
    return None
