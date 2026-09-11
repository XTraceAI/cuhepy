"""This Module provides cryptographic utilities for the XTrace Vec.
    It includes classes and functions for generating and managing cryptographic keys,
    as well as for performing encryption and decryption operations.
    It contains the following modules:

    #. ``commitment``: A module for computing commitment over data.
    #. ``encryption``: A module for performing encryption and decryption operations. 
    #. ``signature``: A module for generating and verifying digital signatures.

    In addition, it provides ``hamming_client_base`` as a base class for crytpographic clients that compute
    hamming distance between two ciphers.

    ``bfv_client`` provides a native GMP BFV implementation of that interface,
    with additional packed-index and packed-response operations (experimental).

    ``bfv_security`` and ``bfv_verified_client`` add optional authenticated
    sessions, private result checks and encrypted private exports. These remain
    experimental and do not make observable decryption feedback safe.
"""
