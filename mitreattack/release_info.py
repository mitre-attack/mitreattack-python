import hashlib

from typing import Optional

from loguru import logger

# This file contains SHA256 hashes for officially released ATT&CK versions
# download_string = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{release}/{domain}-attack/{domain}-attack.json"

ENTERPRISE = {
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
}

MOBILE = {
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
}

ICS = {
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
}

PRE = {
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
}


def get_attack_version(domain: str, stix_file: str = None, stix_content: bytes = None) -> Optional[str]:
    if domain not in [
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
        "pre-attack",
    ]:
        logger.error(
            f"domain must be one of [enterprise-attack | mobile-attack | ics-attack | pre-attack] to determine version"
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

    if domain == "enterprise-attack":
        releases = ENTERPRISE
    elif domain == "mobile-attack":
        releases = MOBILE
    elif domain == "ics-attack":
        releases = ICS
    elif domain == "pre-attack":
        releases = PRE

    for attack_release, hash in releases.items():
        if sha256_hash == hash:
            return attack_release

    if stix_file:
        logger.warning(f"Unknown ATT&CK version for file: {stix_file}")
    else:
        logger.warning("Unknown ATT&CK version")
    return None
