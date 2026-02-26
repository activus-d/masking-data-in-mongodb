from pymongo import MongoClient

# Replace the placeholder values with your Atlas credentials and cluster hostname:
client = MongoClient(
    "mongodb+srv://<USERNAME>:<PASSWORD>@<HOST>/",
    appname="devrel-tutorial-python-masking-data"
)
db = client["mydb"]

cards = db["cards"]

# Insert sample cardholder records into the base collection:
cards.insert_many([
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

# Create a read-only view that masks card_number and redacts cvv and billing_address:
db.command({
    "create": "cards_masked",
    "viewOn": "cards",
    "pipeline": [
        {
            "$project": {
                "_id": 0,
                "cardholder_name": 1,

                # Show only the last four digits of the card number:
                "card_number": {
                    "$concat": [
                        "************",
                        {"$substrCP": ["$card_number", 12, 4]}
                    ]
                },

                # Fully redact the CVV:
                "cvv": "REDACTED",

                "expiry_date": 1,

                # Fully redact the billing address:
                "billing_address": "REDACTED"
            }
        }
    ]
})

# Read from the masked view instead of the base collection:
masked_view = db["cards_masked"]
results = list(masked_view.find({}, {"_id": 0}))

for record in results:
    print(record)