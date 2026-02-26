from pymongo import MongoClient

# Replace the placeholder values with your Atlas credentials and cluster hostname:
client = MongoClient(
    "mongodb+srv://<USERNAME>:<PASSWORD>@<HOST>/",
    appname="devrel-tutorial-python-masking-data"
)
db = client["mydb"]

def get_masked_cards(db, user_role="support_agent"):
    # Build the masking pipeline — role determines what fields are visible:
    pipeline = [
        {
            "$project": {
                "_id": 0,
                "cardholder_name": 1,

                # Show only the last four digits of the card number for all roles:
                "card_number": {
                    "$concat": [
                        "************",
                        {"$substrCP": ["$card_number", 12, 4]}
                    ]
                },

                # CVV only visible for fraud analysts
                "cvv": {
                    "$cond": {
                        "if": {"$eq": ["$$role", "fraud_analyst"]},
                        "then": "$cvv",
                        "else": "REDACTED"
                    }
                },

                # Expiry date only visible for fraud analysts
                "expiry_date": {
                    "$cond": {
                        "if": {"$eq": ["$$role", "fraud_analyst"]},
                        "then": "$expiry_date",
                        "else": "REDACTED"
                    }
                },

                # Fully redact the billing address for all roles:
                "billing_address": "REDACTED"
            }
        }
    ]

    # Pass user_role into the pipeline using `let`
    return list(db["cards"].aggregate(pipeline, let={"role": user_role}))

# Support agents receive masked data for CVV and expiry date:
support_results = get_masked_cards(db, user_role="support_agent")
for record in support_results:
    print(record)

print("---")

# Fraud analysts receive the CVV and expiry date alongside the masked card number:
fraud_results = get_masked_cards(db, user_role="fraud_analyst")
for record in fraud_results:
    print(record)
