import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import pre, keys
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.pre import _open_capsule
from umbral.signing import Signer
from .conftest import parameters

secp_curves = [
    ec.SECP384R1,
    ec.SECP192R1
]


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""

    params = UmbralParameters(curve=curve)

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    signing_pubkey = signing_privkey.get_pubkey()
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_pubkey)

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, 1, 1)

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, receiving_privkey)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_1(N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""

    M, N = 1, 1

    params = UmbralParameters(curve=curve)

    alice_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    alice_pubkey = alice_privkey.get_pubkey()
    plain_data = b'peace at dawn'

    bob_signing_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    bob_verkey = bob_signing_privkey.get_pubkey()
    bob_signer = Signer(bob_signing_privkey)

    bob_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    bob_pubkey = bob_privkey.get_pubkey()

    # Alice does encryption to generate `ciphertext`
    ciphertext, capsule = pre.encrypt(bob_pubkey, plain_data)

    # Bob can decrypt `ciphertext`
    cleartext = pre.decrypt(ciphertext, capsule, bob_privkey)
    assert cleartext == plain_data

    carol_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    carol_pubkey = carol_privkey.get_pubkey()

    carol_signing_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    carol_verkey = carol_signing_privkey.get_pubkey()
    carol_signer = Signer(carol_signing_privkey)

    # Bob sets capsule parameters
    # TODO: verifying should be Carol's verkey, but need to figure out the
    # exact purpose of verification? Who is it protecting? Against.
    capsule.set_correctness_keys(delegating=bob_pubkey,
                                 receiving=carol_pubkey,
                                 verifying=bob_verkey)

    kfrags = pre.split_rekey(bob_privkey, bob_signer, carol_pubkey, M, N)

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, carol_privkey, check_proof=False)
    assert reenc_cleartext == plain_data

    ##---------------------------------CHAINING------------------------------------------

    dave_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    dave_pubkey = dave_privkey.get_pubkey()

    encapsulated_key = _open_capsule(capsule, carol_privkey,
                                     check_proof=True)

    capsule._attached_cfrags = []
    capsule._cfrag_correctness_keys = {"delegating": None,
                                        "receiving": None,
                                        "verifying": None}
    capsule.set_correctness_keys(delegating=bob_pubkey,
                                 receiving=dave_pubkey,
                                 verifying=bob_verkey)

    kfrags_1 = pre.split_rekey(carol_privkey, carol_signer, dave_pubkey, M, N)

    for kfrag in kfrags_1:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag, check_correctness=False)

    reenc_cleartext_1 = pre.decrypt(ciphertext, capsule, dave_privkey,
                                  check_proof=False)
    assert reenc_cleartext_1 == plain_data


@pytest.mark.parametrize("curve", secp_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    test_simple_api(N, M, curve)


def test_public_key_encryption(alices_keys):
    delegating_privkey, _ = alices_keys
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data)
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data
