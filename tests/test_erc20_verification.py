from scam_intelligence.investigation import ScamInvestigator
from scam_intelligence.schemas import Transaction


TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

TOKEN = "0x9af45623f959c77901426c4b991be6a2499efa9a"
FROM = "0x9bdbbd6ff7889e1cb668c21c5da3c8a73a7742ae"
TO = "0x46bc8d000c6c3b4ed2667e85f04364e25e3b0265"
VALUE = "90841758000000000"


def make_tx():
    return Transaction(
        tx_hash="0xtest",
        network="ethereum",
        from_address=FROM,
        to_address=TO,
        value=VALUE,
        token=TOKEN,
        metadata={
            "type": "ERC20_TRANSFER",
            "log_index": 1206,
        },
    )


def make_receipt():
    return {
        "status": "0x1",
        "logs": [
            {
                "address": TOKEN,
                "logIndex": "0x4b6",
                "topics": [
                    TRANSFER_TOPIC,
                    "0x000000000000000000000000" + FROM[2:],
                    "0x000000000000000000000000" + TO[2:],
                ],
                "data": hex(int(VALUE)),
            }
        ],
    }


def test_valid_erc20_transfer():
    result = ScamInvestigator._erc20_transfer_matches(
        make_tx(),
        make_receipt(),
    )

    assert result["matched"] is True
    assert result["token"] == TOKEN
    assert result["from"] == FROM
    assert result["to"] == TO
    assert result["value"] == VALUE
    assert result["log_index"] == 1206


def test_invalid_value_is_rejected():
    tx = make_tx()
    tx.value = "1"

    result = ScamInvestigator._erc20_transfer_matches(
        tx,
        make_receipt(),
    )

    assert result["matched"] is False


def test_invalid_token_is_rejected():
    tx = make_tx()
    tx.token = "0x0000000000000000000000000000000000000001"

    result = ScamInvestigator._erc20_transfer_matches(
        tx,
        make_receipt(),
    )

    assert result["matched"] is False


def test_hex_log_index_matches_decimal_index():
    result = ScamInvestigator._erc20_transfer_matches(
        make_tx(),
        make_receipt(),
    )

    assert result["matched"] is True


def test_wrong_log_index_is_rejected():
    tx = make_tx()
    tx.metadata["log_index"] = 1207

    result = ScamInvestigator._erc20_transfer_matches(
        tx,
        make_receipt(),
    )

    assert result["matched"] is False
