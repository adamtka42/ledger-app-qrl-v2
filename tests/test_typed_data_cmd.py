from copy import deepcopy
import json
import re

import pytest
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.bip import pack_derivation_path
from ragger.error import ExceptionRAPDU

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors
from application_client.personal_message import personal_message_hash
from application_client.transaction_helpers import SIGNING_CONTEXT, get_public_key_chunks, get_signature_chunks
from application_client.typed_data import (
    DOMAIN_TYPE, MAX_PAYLOAD, PATH, encode_typed_data, permission_example, typed_data_hash, wide_example,
)


def nested_example():
    doc = permission_example()
    doc["types"] = {
        DOMAIN_TYPE: doc["types"][DOMAIN_TYPE],
        "Mail": [{"name": "from", "type": "Person"}, {"name": "contents", "type": "string"}],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
    }
    doc["primaryType"] = "Mail"
    doc["message"] = {"from": {"name": "Alice", "wallet": "Q" + "11" * 64}, "contents": "Hello\nEND OF MESSAGE"}
    return doc


def array_example():
    doc = wide_example()
    doc["types"]["WideValues"] = [{"name": "limits", "type": "uint16[]"},
                                    {"name": "empty", "type": "address[]"},
                                    {"name": "enabled", "type": "bool"}]
    doc["message"] = {"limits": [0, 65535], "empty": [], "enabled": True}
    return doc


def long_example():
    doc = wide_example()
    doc["types"]["WideValues"] = [{"name": "text", "type": "string"}, {"name": "raw", "type": "bytes"}]
    doc["message"] = {"text": "W" * 229 + "END OF TEXT" + "\n" * 16,
                      "raw": "0x" + bytes(range(256)).hex()}
    return doc


def negative_example():
    doc = wide_example()
    doc["types"]["WideValues"] = [{"name": "amount", "type": "int512"}]
    doc["message"] = {"amount": -(2**511)}
    return doc


def deep_example():
    doc = wide_example()
    doc["types"]["WideValues"] = [{"name": "one", "type": "A"}]
    doc["types"]["A"] = [{"name": "two", "type": "B"}]
    doc["types"]["B"] = [{"name": "three", "type": "C"}]
    doc["types"]["C"] = [{"name": "value", "type": "uint512"}]
    doc["message"] = {"one": {"two": {"three": {"value": str(2**512 - 1)}}}}
    return doc


def account_field_example():
    doc = permission_example()
    doc["types"]["SpendingPermission"][0]["name"] = "Account"
    doc["message"]["Account"] = doc["message"].pop("spender")
    return doc


def identifier_example():
    doc = nested_example()
    doc["types"] = {
        DOMAIN_TYPE: doc["types"][DOMAIN_TYPE],
        "Mail_1": [{"name": "_from", "type": "Person_2[]"}, {"name": "_contents", "type": "string"}],
        "Person_2": [{"name": "_name", "type": "string"}, {"name": "wallet_2", "type": "address"}],
    }
    doc["primaryType"] = "Mail_1"
    doc["message"] = {"_from": [{"_name": "Alice", "wallet_2": "Q" + "11" * 64}], "_contents": "Hello"}
    return doc


def shared_depth_example(over_depth, reverse_fields, reverse_types, array_count):
    """Reach Shared first by a short path, then by a longer path near the limit."""
    reference = "Leaf" if array_count is None else "Leaf[]"
    leaf_value = {} if array_count is None else [{} for _ in range(array_count)]
    shared = {"leaf": leaf_value}
    fields = [{"name": "shallow", "type": "Shared"}, {"name": "deep", "type": "A"}]
    if reverse_fields:
        fields.reverse()
    types = {
        DOMAIN_TYPE: [{"name": "name", "type": "string"}],
        "Root": fields,
        "A": [{"name": "next", "type": "B" if over_depth else "Shared"}],
        "Shared": [{"name": "leaf", "type": reference}],
        "Leaf": [],
    }
    deep = {"next": deepcopy(shared)}
    if over_depth:
        types["B"] = [{"name": "next", "type": "Shared"}]
        deep = {"next": deep}
    if reverse_types:
        types = dict(reversed(list(types.items())))
    return {"types": types, "primaryType": "Root", "domain": {"name": "Depth test"},
            "message": {"shallow": shared, "deep": deep}}


def start(backend, length, path=PATH):
    return backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=0, p2=0,
                            data=pack_derivation_path(path) + length.to_bytes(4, "big"))


def send(backend, data=b"", *, p1=2, p2=0):
    return backend.exchange(cla=CLA, ins=InsType.SIGN_TYPED_DATA, p1=p1, p2=p2, data=data)


@pytest.mark.parametrize("sample,decision", [
    ("permission", "approve"), ("wide", "approve"), ("nested", "approve"),
    ("arrays", "approve"), ("long", "approve"), ("deep", "approve"),
    ("account_field", "approve"), ("identifiers", "approve"),
    ("negative", "approve"), ("permission", "reject"),
])
def test_typed_data_review(backend, scenario_navigator, monkeypatch, sample, decision):
    doc = {"permission": permission_example, "wide": wide_example, "nested": nested_example,
           "arrays": array_example, "long": long_example, "deep": deep_example,
           "account_field": account_field_example, "identifiers": identifier_example,
           "negative": negative_example}[sample]()
    payload = encode_typed_data(doc)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    name = f"test_typed_data_{sample}_{decision}"
    # Every fragment must stay on the mandatory review path on touch devices.
    screen_texts = []
    raw_pages = {}
    compare_snapshot = backend.compare_screen_with_snapshot

    def capture_screen(*args, **kwargs):
        result = compare_snapshot(*args, **kwargs)
        texts = [event.get("text", "") for event in backend.get_current_screen_content()["events"]]
        assert "More" not in texts
        assert not any(re.search(r"\(\d+/\d+\).*\(\d+/\d+\)", text) for text in texts)
        screen_texts.extend(texts)
        if sample == "long":
            for index, text in enumerate(texts):
                if re.fullmatch(r"raw(?: \(\d+/\d+\))?", text):
                    value = "".join(t for t in texts[index + 1:]
                                    if re.fullmatch(r"(?:0x)?[0-9a-f]+", t))
                    if text in raw_pages:
                        assert raw_pages[text] == value
                    raw_pages[text] = value
        return result

    monkeypatch.setattr(backend, "compare_screen_with_snapshot", capture_screen)
    if decision == "reject":
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_typed_data(PATH, payload):
                scenario_navigator.review_reject(test_name=name)
        assert exc.value.status == Errors.SW_DENY
        with pytest.raises(ExceptionRAPDU) as exc:
            send(backend, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
        return
    with client.sign_typed_data(PATH, payload):
        scenario_navigator.review_approve(test_name=name)
    if sample == "account_field":
        assert any(re.fullmatch(r"Sign with(?: \(\d+/\d+\))?", text) for text in screen_texts)
        assert any(re.fullmatch(r"Account(?: \(\d+/\d+\))?", text) for text in screen_texts)
    if sample == "long":
        # Both the text and the 256-byte hex value must reach their final bytes.
        visible = "".join(screen_texts)
        # The marker may cross Nano pages; its final word must still be visible.
        assert "TEXT" in visible
        assert "".join(raw_pages.values()) == doc["message"]["raw"]
    for ins in (InsType.SIGN_TX, InsType.SIGN_PERSONAL_MESSAGE):
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=ins, p1=2, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
    signature = get_signature_chunks(backend, client.get_async_response().data, ins=InsType.SIGN_TYPED_DATA)
    digest = typed_data_hash(doc)
    assert len(signature) == 4627
    assert ML_DSA_87.verify(public_key, digest, signature, ctx=SIGNING_CONTEXT)
    assert not ML_DSA_87.verify(public_key, digest, signature, ctx=b"")
    assert not ML_DSA_87.verify(public_key, personal_message_hash(json.dumps(doc).encode()), signature, ctx=SIGNING_CONTEXT)
    changed = deepcopy(doc)
    changed["domain"]["name"] += "!"
    assert not ML_DSA_87.verify(public_key, typed_data_hash(changed), signature, ctx=SIGNING_CONTEXT)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("kind,value", [
    ("int128", -(2**127)), ("int256", -(2**255)), ("int512", -(2**511)),
    ("string", "-" + "63739682910296196688" * 6),
    ("string", "_" + "63739682910296196688" * 6),
    ("string", " " + "63739682910296196688" * 6),
    ("string", "Line\n_" + "63739682910296196688" * 6),
    ("string", "W" * 229 + "END OF TEXT" + "\n" * 16),
    ("string", "\n" * 16 + "_" + "63739682910296196688" * 6),
], ids=["minimum_int128", "minimum_int256", "minimum_int512", "hyphen", "underscore", "space", "line_start",
        "trailing_lf", "leading_lf"])
def test_typed_data_rendered_value(backend, scenario_navigator, monkeypatch, kind, value):
    field = "text" if kind == "string" else "amount"
    doc = wide_example()
    doc["types"]["WideValues"] = [{"name": field, "type": kind}]
    doc["message"] = {field: value}
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    pages = {}
    compare_text = backend.compare_screen_with_text

    def capture_page(pattern):
        texts = [event.get("text", "") for event in backend.get_current_screen_content()["events"]]
        assert "More" not in texts
        assert not any(re.search(r"\(\d+/\d+\).*\(\d+/\d+\)", text) for text in texts)
        for index, title in enumerate(texts):
            if re.fullmatch(rf"{field}(?: \(\d+/\d+\))?", title):
                # Footer controls are not part of the field. Keep all value
                # characters, including spaces, and ignore visual line breaks.
                rendered = "".join(text for text in texts[index + 1:]
                                   if text != "Reject" and not re.fullmatch(r"\d+ of \d+", text))
                if title in pages:
                    assert pages[title] == rendered
                pages[title] = rendered
        return compare_text(pattern)

    monkeypatch.setattr(backend, "compare_screen_with_text", capture_page)
    with client.sign_typed_data(PATH, encode_typed_data(doc)):
        scenario_navigator.review_approve(do_comparison=False)
    expected = str(value).replace("\n", "")
    displayed = "".join(pages.values()).replace("\n", "")
    assert displayed == expected, (len(displayed), len(expected), pages)
    signature = get_signature_chunks(backend, client.get_async_response().data, ins=InsType.SIGN_TYPED_DATA)
    assert ML_DSA_87.verify(public_key, typed_data_hash(doc), signature, ctx=SIGNING_CONTEXT)


@pytest.mark.parametrize("which", ["chain", "contract", "name", "version", "spender", "limit", "nonce", "type"])
def test_typed_data_digest_binds_each_field(backend, scenario_navigator, which):
    doc = permission_example()
    original_digest = typed_data_hash(doc)
    if which in ("chain", "contract", "name", "version"):
        key = {"chain": "chainId", "contract": "verifyingContract"}.get(which, which)
        doc["domain"][key] = "Q" + "33" * 64 if which == "contract" else doc["domain"][key] + "2"
    elif which == "type":
        doc["types"]["SpendingPermission"][1]["type"] = "uint512"
    else:
        doc["message"][which] = "Q" + "33" * 64 if which == "spender" else str(int(doc["message"][which]) + 1)
    client = BoilerplateCommandSender(backend)
    client.get_public_key(PATH)
    public_key = get_public_key_chunks(backend)
    with client.sign_typed_data(PATH, encode_typed_data(doc)):
        # Screen layout is covered by test_typed_data_review; this test checks
        # that each changed field actually reaches the device's signed digest.
        scenario_navigator.review_approve(do_comparison=False)
    signature = get_signature_chunks(backend, client.get_async_response().data, ins=InsType.SIGN_TYPED_DATA)
    changed_digest = typed_data_hash(doc)
    assert changed_digest != original_digest
    assert ML_DSA_87.verify(public_key, changed_digest, signature, ctx=SIGNING_CONTEXT)
    assert not ML_DSA_87.verify(public_key, original_digest, signature, ctx=SIGNING_CONTEXT)


@pytest.mark.parametrize("case", ["primary", "nested", "array", "unused", "reference"])
def test_encoder_rejects_underscore_type_names(case):
    doc = nested_example()
    if case == "primary":
        doc["types"]["_Mail"] = doc["types"].pop("Mail")
        doc["primaryType"] = "_Mail"
    elif case in ("nested", "array"):
        doc["types"]["_Inner"] = doc["types"].pop("Person")
        doc["types"]["Mail"][0]["type"] = "_Inner[]" if case == "array" else "_Inner"
        if case == "array":
            doc["message"]["from"] = [doc["message"]["from"]]
    elif case == "unused":
        doc["types"]["_Unused"] = []
    else:
        doc["types"]["Mail"][0]["type"] = "_Inner"
    with pytest.raises(ValueError, match="Type names must start with an ASCII letter"):
        encode_typed_data(doc)


def unchecked_schema(types, primary=1):
    result = bytes([1, len(types), primary])
    for name, fields in types:
        result += bytes([len(name)]) + name.encode() + bytes([len(fields)])
        for field, type_name in fields:
            for text in (field, type_name):
                result += bytes([len(text)]) + text.encode()
    return result


@pytest.mark.parametrize("over_depth", [False, True])
@pytest.mark.parametrize("reverse_fields", [False, True])
@pytest.mark.parametrize("reverse_types", [False, True])
@pytest.mark.parametrize("array_count", [None, 0, 1])
def test_shared_type_depth_limit(backend, scenario_navigator, over_depth, reverse_fields,
                                 reverse_types, array_count):
    doc = shared_depth_example(over_depth, reverse_fields, reverse_types, array_count)
    names = list(doc["types"])
    # Construct wire data independently so invalid documents reach the device
    # even after the client encoder correctly rejects them.
    schema = [(name, [(field["name"], field["type"]) for field in fields])
              for name, fields in doc["types"].items()]
    domain = doc["domain"]["name"].encode("ascii")
    payload = unchecked_schema(schema, primary=names.index("Root")) + len(domain).to_bytes(2, "big") + domain
    if array_count is not None:
        payload += bytes([array_count, array_count])  # Each Shared contains one Leaf[]; Leaf has no fields.
    client = BoilerplateCommandSender(backend)
    if over_depth:
        with pytest.raises(ValueError, match="Cyclic/deep type graph"):
            encode_typed_data(doc)
        with pytest.raises(ExceptionRAPDU) as exc:
            with client.sign_typed_data(PATH, payload):
                pass
        assert exc.value.status == Errors.SW_TYPED_DATA_INVALID
        with pytest.raises(ExceptionRAPDU) as exc:
            send(backend, p2=1)
        assert exc.value.status == Errors.SW_BAD_STATE
    else:
        assert encode_typed_data(doc) == payload
        client.get_public_key(PATH)
        public_key = get_public_key_chunks(backend)
        with client.sign_typed_data(PATH, payload):
            scenario_navigator.review_approve(do_comparison=False)
        signature = get_signature_chunks(backend, client.get_async_response().data, ins=InsType.SIGN_TYPED_DATA)
        assert ML_DSA_87.verify(public_key, typed_data_hash(doc), signature, ctx=SIGNING_CONTEXT)


def invalid_payload(case):
    if case in ("hash_only", "ethereum_preimage"):
        return typed_data_hash(permission_example()) if case == "hash_only" else b"\x19\x01" + b"\0" * 64
    doc = wide_example()
    payload = bytearray(encode_typed_data(doc))
    if case == "version": payload[0] = 2
    elif case == "primary": payload[2] = 0
    elif case == "trailing": payload += b"\0"
    elif case == "truncated": payload = payload[:-1]
    elif case == "bad_text": payload[payload.index(b"QRL VM64 Golden")] = 0xff
    elif case == "integer_padding":
        doc["types"]["WideValues"][0]["type"] = "uint8"
        doc["message"]["amount"] = 1
        payload = bytearray(encode_typed_data(doc))
        payload[-128] = 1
    elif case == "bool":
        doc["types"]["WideValues"] = [{"name": "enabled", "type": "bool"}]
        doc["message"] = {"enabled": False}
        payload = bytearray(encode_typed_data(doc)); payload[-1] = 2
    elif case == "review_budget":
        doc["types"]["WideValues"] = [{"name": f"field{i}", "type": "uint512"} for i in range(31)]
        doc["message"] = {f"field{i}": str(2**512 - 1) for i in range(31)}
        doc["types"]["WideValues"][0]["type"] = "uint512[]"
        doc["message"]["field0"] = [str(2**512 - 1)] * 8
        payload = encode_typed_data(doc)
    elif case.startswith("underscore_"):
        # Encode a complete valid document first, then bypass the host validator.
        # Equal-length substitutions preserve lengths, references and value bytes.
        doc = nested_example()
        if case == "underscore_array":
            doc["types"]["Mail"][0]["type"] = "Person[]"
            doc["message"]["from"] = [doc["message"]["from"]]
        if case == "underscore_unused":
            doc["types"]["Spare"] = []
        original, replacement = {
            "underscore_primary": (b"Mail", b"_ail"),
            "underscore_nested": (b"Person", b"_Inner"),
            "underscore_array": (b"Person", b"_Inner"),
            "underscore_unused": (b"Spare", b"_pare"),
        }[case]
        payload = encode_typed_data(doc).replace(original, replacement)
    else:
        domain = (DOMAIN_TYPE, [("name", "string")])
        variants = {
            "cycle": [domain, ("A", [("next", "B")]), ("B", [("next", "A")])],
            "unknown": [domain, ("A", [("bad", "Unknown")])],
            "duplicate_type": [domain, ("A", []), ("A", [])],
            "duplicate_field": [domain, ("A", [("same", "bool"), ("same", "bool")])],
            "bad_identifier": [domain, ("A", [("bad\nname", "bool")])],
            "device_label": [domain, ("A", [("Sign with", "address")])],
            "bad_width": [domain, ("A", [("bad", "uint7")])],
            "fixed_array": [domain, ("A", [("bad", "uint256[2]")])],
            "ethereum_domain": [("EIP712Domain", [("name", "string")]), ("A", [])],
            "domain_type": [(DOMAIN_TYPE, [("chainId", "string")]), ("A", [])],
            "shadow_type": [domain, ("bool", [])],
            "deep_schema": [domain, ("A", [("b", "B")]), ("B", [("c", "C")]),
                            ("C", [("d", "D")]), ("D", [("e", "E")]), ("E", [])],
        }
        payload = unchecked_schema(variants[case])
    return bytes(payload)


@pytest.mark.parametrize("case", ["hash_only", "ethereum_preimage", "version", "primary", "trailing",
    "truncated", "bad_text", "integer_padding", "bool", "review_budget", "cycle", "unknown",
    "duplicate_type", "duplicate_field", "bad_identifier", "device_label", "bad_width", "fixed_array",
    "ethereum_domain", "domain_type", "shadow_type", "deep_schema",
    "underscore_primary", "underscore_nested", "underscore_array", "underscore_unused"])
def test_invalid_typed_data_aborts(backend, case):
    payload = invalid_payload(case)
    with pytest.raises(ExceptionRAPDU) as exc:
        with BoilerplateCommandSender(backend).sign_typed_data(PATH, payload):
            pass
    assert exc.value.status == Errors.SW_TYPED_DATA_INVALID
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("payload", [b"", b"\0", pack_derivation_path(PATH),
    pack_derivation_path(PATH) + b"\0" * 3,
    pack_derivation_path(PATH) + (MAX_PAYLOAD + 1).to_bytes(4, "big"),
    pack_derivation_path("m/44'/60'/0'/0/0") + (128).to_bytes(4, "big")])
def test_typed_data_bad_start(backend, payload):
    start(backend, 100)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, payload, p1=0)
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, b"x", p1=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("p1,p2", [(3, 0), (0, 1), (1, 1), (2, 18)])
def test_typed_data_bad_parameters(backend, p1, p2):
    start(backend, 100)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, b"x", p1=p1, p2=p2)
    assert exc.value.status == Errors.SW_WRONG_P1P2
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, b"x", p1=1)
    assert exc.value.status == Errors.SW_BAD_STATE


@pytest.mark.parametrize("expected,data,p1", [(3, b"", 1), (3, b"", 2), (3, b"1234", 2),
                                             (3, b"12", 2), (3, b"123", 1)])
def test_typed_data_lengths(backend, expected, data, p1):
    start(backend, expected)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, data, p1=p1)
    assert exc.value.status == Errors.SW_WRONG_DATA_LENGTH


def test_typed_data_sessions_are_isolated(backend):
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, b"x", p1=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    start(backend, 100)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, p2=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    BoilerplateCommandSender(backend).get_public_key(PATH)
    with pytest.raises(ExceptionRAPDU) as exc:
        send(backend, b"x", p1=1)
    assert exc.value.status == Errors.SW_BAD_STATE
    for ins in (InsType.SIGN_TX, InsType.SIGN_PERSONAL_MESSAGE):
        start(backend, 100)
        with pytest.raises(ExceptionRAPDU) as exc:
            backend.exchange(cla=CLA, ins=ins, p1=1, p2=0, data=b"x")
        assert exc.value.status == Errors.SW_BAD_STATE
        with pytest.raises(ExceptionRAPDU) as exc:
            send(backend, b"x", p1=1)
        assert exc.value.status == Errors.SW_BAD_STATE
