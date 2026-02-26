import uuid
from datetime import datetime, timezone
from pymongo import MongoClient

# Replace the placeholder values with your Atlas credentials and cluster hostname:
client = MongoClient(
    "mongodb+srv://<USERNAME>:<PASSWORD>@<HOST>/",
    appname="devrel-tutorial-python-masking-data"
)
db = client["mydb"]

# The vault stores every token-to-value mapping:
vault_coll = db["token_vault"]

# The payments collection stores tokens instead of raw card numbers:
payments_coll = db["payments"]

def tokenize(sensitive_value):
    # Return the existing token if one already exists for this value:
    existing = vault_coll.find_one({"original_value": sensitive_value})

    if existing:
        return existing["token"]

    # Generate a new UUID token and store the mapping in the vault:
    token = str(uuid.uuid4())

    vault_coll.insert_one({
        "token": token,
        "original_value": sensitive_value,
        "created_at": datetime.now(timezone.utc)
    })

    return token


def detokenize(token):
    # Look up the token in the vault and return the original value:
    record = vault_coll.find_one({"token": token})

    if record:
        return record["original_value"]

    return None

card_number = "4111111111111111"

# Convert the card number to a token before storing the payment record:
card_token = tokenize(card_number)

payments_coll.insert_one({
    "payment_id": "PAY-2025-001",
    "customer_id": "CUST-456",
    "card_token": card_token,
    "amount": 149.99,
    "status": "confirmed"
})

print(f"Stored token: {card_token}")

# Fetch the payment record and detokenize the card token to recover the original number:
payment = payments_coll.find_one({"payment_id": "PAY-2025-001"})
original_card = detokenize(payment["card_token"])

print(f"Original card number: {original_card}")