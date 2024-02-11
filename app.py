from flask import Flask, request, redirect, url_for
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime
from contact import Contact
from invoice import Invoice
import re
import webbrowser
import csv
import base64
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content

app = Flask(__name__)

# Define your Xero API credentials and redirect URI
CLIENT_ID = '34BEA5134E024579ABDD240E66C566F5'
CLIENT_SECRET = 'RbylkCIYynciLTeDEMYHij0m7tIO8Mcjmdn3Q-eQ7I1BNpYq'
REDIRECT_URI = "https://bx.richardbaldwin.nz/callback"

app.logger.setLevel(logging.INFO)

if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)
    



# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

# The Main Page which does nothing
@app.route('/')
def index():
    app.logger.info(f'Info Log')
    app.logger.error("Error Log")
    return "Hello World!"


# The endpoint to which SendGrid will send the parsed email
@app.route('/append-message', methods=['POST'])
def sendgrid_parser():
    file_path = 'messages.txt'
    if request.method == 'POST':
        # Uncomment this block if expecting JSON data
        # if request.is_json:
        #     data = request.get_json()
        #     # Process JSON data here

        try:
            # encode HTML entities to prevent XSS attacks
            # message_body_text = html.escape(request.form['text'])
            message_subject = request.form['subject']
            message_text = request.form['text']

            # Open the file and append the message
            with open(file_path, 'a') as file:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file.write(f"Called at: {current_time}\n")
                file.write("this has been called" + '\n\n')
                file.write("1" + '\n')
                file.write("Subject:" + '\n' + message_subject + '\n')
                file.write("Text:" + '\n' + message_text + '\n')

                # Log specific fields from request.form
                file.write("Form Data:" + '\n')
                for key, value in request.form.items():
                    file.write(f"{key}: {value}\n")

            return "Message appended to file", 200
        except Exception as e:
            # Handle exceptions
            return f"An error occurred: {e}", 500
        




@app.route('/post-endpoint', methods=['GET', 'POST'])
def handle_post():
    #app.logger.info(f'Info level log')
    """
    Handles POST requests and extracts JSON data from the request.
    """
    if request.is_json:
        json_data = request.get_json()

        # print the json_data to the error log
        #app.logger.info(f"Printing data:")
        #app.logger.info(json_data)


        # Print the json_data to the console
        print(f"Received data: {json_data}")
        return "Data received and printed to console", 200
    else:
        print(f"Failed")
        return "Request body must be JSON", 400

if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)  # Enable debug mode for easier development
    print(f"This is running on port {PORT}")


def process_biblio(text):
    email_match = re.search(r"\*Customer Email: \*.*<(.+?)>", text)
    phone_match = re.search(r"\*Customer Phone: \*([0-9 ]+)", text)

    EmailAddress = email_match.group(1) if email_match else None
    Phone = phone_match.group(1) if phone_match else None

    lines = text.strip().split('\n')
    ship_to_index = lines.index("*Ship to:*") + 1
    Name = lines[ship_to_index].strip()
    AddressLine1 = lines[ship_to_index + 1].strip()
    City_PostalCode = lines[ship_to_index + 2].strip()

    City, PostalCode = re.match(r"(.*) (\d+)", City_PostalCode).groups()

    sub_total_match = re.search(r"Subtotal: NZ\$(\d+\.\d+)", text)
    total_match = re.search(r"Total: NZ\$(\d+\.\d+)", text)

    sub_total = sub_total_match.group(1) if sub_total_match else None
    total = total_match.group(1) if total_match else None

    print(f"Email Address: {EmailAddress}")
    print(f"Phone: {Phone}")
    print(f"Name: {Name}")
    print(f"AddressLine1: {AddressLine1}")
    print(f"City: {City}")
    print(f"PostalCode: {PostalCode}")
    print(f"Subtotal: {sub_total}")
    print(f"Total: {total}")

    contact = Contact(ContactID=-1, Name=Name, EmailAddress=EmailAddress, Phone=Phone)
    contact.add_address(AddressType="POBOX", AddressLine1=AddressLine1, City=City, PostalCode=PostalCode)
    print(contact)
    # call Xero api, send contact and get the contact_id

    invoice = Invoice(contact=contact, sub_total=sub_total, total=total, currency_code="NZD", invoice_id="123", invoice_number="INV123")
    print(invoice)


def find_keyword_in_txt(file_path, keyword):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            if keyword in content:
                print("this is a mail from " + keyword)
                process_biblio(content)
            else:
                return "it is from fishpond"

    except FileNotFoundError:
        return "file not found"


if __name__ == "__main__":
    file_path = 'messages.txt'
    keyword = 'Biblio.co.nz'
    result = find_keyword_in_txt(file_path, keyword)

# Add data to a CSV file
def collect_data():
    data = request.form.to_dict()
    with open('daily_data.csv', 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data.keys())
        writer.writerow(data)
    return 'Data received'


# Working Test Email Code
# @app.route('/send_test_email')
def send_email():
    sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
    from_email = Email("richard@monument.page")  # Change to your verified sender
    to_email = To("richard@empyre.co")  # Change to your recipient
    subject = "Sending with SendGrid is Fun"
    content = Content("text/plain", "and easy to do anywhere, even with Python")
    mail = Mail(from_email, to_email, subject, content)

    # Get a JSON-ready representation of the Mail object
    mail_json = mail.get()

    # Send an HTTP POST request to /mail/send
    response = sg.client.mail.send.post(request_body=mail_json)

    # This is the response from the SendGrid API, but it's not strictly required
    #print(response.status_code)
    #print(response.headers)





# Xero Code
# Define the path to the file where tokens will be stored
TOKEN_FILE_PATH = 'xero_tokens2.txt'

def save_tokens(access_token, refresh_token, tenant_id):
    # Implement logic to save tokens securely (e.g., in a database or encrypted file)
    with open(TOKEN_FILE_PATH, 'w') as f:
        f.write(f"access_token={access_token}\n")
        f.write(f"refresh_token={refresh_token}\n")
        f.write(f"tenant_id={tenant_id}\n")

def get_refresh_token():
    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, 'r') as f:
            tokens = f.readlines()
            for token in tokens:
                if token.startswith("refresh_token="):
                    refresh_token = token.split("=")[1].strip()
                    return refresh_token
    return None

def get_tenant_id():
    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, 'r') as f:
            tokens = f.readlines()
            for token in tokens:
                if token.startswith("tenant_id="):
                    tenant_id = token.split("=")[1].strip()
                    return tenant_id
    return None

def refresh_access_token():
    token_url = "https://identity.xero.com/connect/token"
    headers = {
        "Authorization": "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode(),
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": get_access_token()
    }
    response = request.post(token_url, headers=headers, data=data)
    if response.status_code == 200:
        new_access_token = response.json().get("access_token")
        new_refresh_token = response.json().get("refresh_token")
        tenant_id = get_tenant_id()  # Retrieve tenant ID from storage
        # Save tokens and tenantID for future use
        save_tokens(new_access_token, new_refresh_token, tenant_id)
        return new_access_token
    else:
        # Handle the case where token refreshing fails
        print("Token refreshing failed")
        return "Token refreshing failed"
    
def get_access_token():
    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, 'r') as f:
            tokens = f.readlines()
            access_token = None
            for token in tokens:
                if token.startswith("access_token="):
                    access_token = token.split("=")[1].strip()
                    break
            return access_token
    return None

#Implement the create_invoice function to create an invoice in Xero
def create_invoice(xero_invoice, access_token, tenant_id):
    create_invoice_url = "https://api.xero.com/api.xro/2.0/Invoices"
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json",
        "xero-tenant-id": tenant_id
    }
    response = request.post(create_invoice_url, headers=headers, json=xero_invoice)
    if response.status_code == 200:
        return "Invoice created successfully"
    else:
        error_message = f"Failed to create invoice: {response.text}"
        print(error_message)
        return error_message

# Define the home route    
@app.route('/')
def home():
    return "Welcome to the Invoice Creation App!!"

# Define the login route to start the OAuth 2.0 flow
@app.route('/login')
def login():
    # Redirect the user to the Xero authorization URL (same as before)
    xero_authorization_url = (
        "https://login.xero.com/identity/connect/authorize?"
        f"response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        "&scope=openid profile email accounting.transactions&state=123"
    )
    return redirect(xero_authorization_url)

# Define the callback route to handle the authorization code automatically
@app.route('/callback')
def callback():
    # Get the authorization code from the query parameters
    code = request.args.get('code')
    tenant_id = request.args.get('tenantId')
    
    # Make a POST request to exchange the authorization code for an access token
    token_url = "https://identity.xero.com/connect/token"
    headers = {
        "Authorization": "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode(),
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI
    }
    response = request.post(token_url, headers=headers, data=data)

    # Handle the response
    if response.status_code == 200:
        access_token = response.json().get("access_token")
        refresh_token = response.json().get("refresh_token")
        save_tokens(access_token, refresh_token, tenant_id)
        return "Authorization successful. You can now create invoices."
    else:
        return "Failed to exchange the authorization code for an access token."

# Define the create_invoice route to create an invoice in Xero once authorized
@app.route('/create_invoice')
def create_invoice_route():
    # Check if access token is expired or about to expire
    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        # Proceed with invoice creation using the refreshed access token
        tenant_id = get_tenant_id()

        # Replace this example invoice data with your actual data
        xero_invoice = {
            "Type": "ACCREC",
            "Contact": {
                "Name": "Customer Name",
                "Addresses": [{
                    "AddressType": "STREET",
                    "AddressLine1": "123 Main Street",
                    "PostalCode": "12345"
                }]
            },
            "Date": "2023-01-01",
            "DueDate": "2023-01-15",
            "LineItems": [{
                "Description": "Example Item",
                "Quantity": 1,
                "UnitAmount": 100.00,
                "AccountCode": "200"
            }], 
            "Reference": "INV-001"
        }
        result = create_invoice(xero_invoice, access_token, tenant_id)
        return result
    else:
        return "Failed to create invoice. Unable to obtain access token."
