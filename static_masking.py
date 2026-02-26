from faker import Faker
from pymongo import MongoClient

fake = Faker()

# Replace the placeholder values with your Atlas credentials and cluster hostname:
client = MongoClient(
    "mongodb+srv://<USERNAME>:<PASSWORD>@<HOST>/",
    appname="devrel-tutorial-python-masking-data"
)

# Point to separate source and target collections:
source_coll = client["production"]["cards"]
target_coll = client["development"]["cards"]

# Seed the source collection with sample production-like cardholder records:
source_coll.insert_many([
    {
        "cardholder_name": "Jane Doe",
        "card_number": "4111111111111111",
        "cvv": "123",
        "expiry_date": "12/26",
        "billing_address": "123 Main St, Springfield, OH 45501"
    },
    {
        "cardholder_name": "John Smith",
        "card_number": "5500005555555559",
        "cvv": "456",
        "expiry_date": "08/27",
        "billing_address": "456 Elm St, Columbus, OH 43215"
    }
])

def mask_document(doc):
    # Replace every sensitive field with a Faker-generated value:
    return {
        "cardholder_name": fake.name(),

        # Generate a random 16-digit card number:
        "card_number": fake.credit_card_number(),

        # Generate a random 3-digit CVV:
        "cvv": fake.credit_card_security_code(),

        # Generate a random future expiry date:
        "expiry_date": fake.credit_card_expire(),

        # Generate a random address on one line:
        "billing_address": fake.address().replace("\n", ", ")
    }

def run_static_masking():
    # Drop the target collection before each run to avoid stale data:
    target_coll.drop()

    cursor = source_coll.find({})
    masked_docs = []

    for doc in cursor:
        masked_docs.append(mask_document(doc))

    if masked_docs:
        target_coll.insert_many(masked_docs)
        print(f"Masked and copied {len(masked_docs)} documents.")
    else:
        print("No documents found in source collection.")

run_static_masking()

# Retrieve one sample document from the target collection to confirm masking:
sample = target_coll.find_one({}, {"_id": 0})
print(sample)