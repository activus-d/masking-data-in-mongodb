# MongoDB data masking — Python examples

This repository contains the code samples for the How to implement data masking in MongoDB tutorial. It covers four data masking techniques:

- view-based masking
- aggregation pipeline masking
- static data masking
- tokenization

The techniques are implemented in Python using a MongoDB Atlas free tier cluster.

Each technique has its own Python file. Before you run any file, replace the `<USERNAME>`, `<PASSWORD>`, and `<HOST>` placeholders in the connection string with your Atlas credentials and cluster hostname.

## Clone the repository

Run the following command to clone the repository to your machine:

```bash
git clone https://github.com/<your-username>/mongodb-masking.git
```

## Set up your environment

Navigate into the project folder:

```bash
cd mongodb-masking
```

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

On Windows, activate the virtual environment with:

```bash
venv\Scripts\activate
```

Install the required packages:

```bash
python -m pip install pymongo faker
```

## Run the files

Each file demonstrates one masking technique. Run them individually with the following commands:

```bash
python view_masking.py
```

```bash
python aggregation_masking.py
```

```bash
python static_masking.py
```

```bash
python tokenization.py
```

Refer to the tutorial for a full explanation of what each script does and when to use each technique.
