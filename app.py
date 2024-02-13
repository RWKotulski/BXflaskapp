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
from flask import Flask
import requests
import base64

app = Flask(__name__)

if __name__ == "__main__":
    file_path = 'messages.txt'
    keyword = 'Biblio.co.nz'
    


# Define your Xero API credentials and redirect URI
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
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

            # Call the function to process the file
            result = finding_source(file_path)

            return "Invoice Created", 200
        except Exception as e:
            # Handle exceptions
            return f"An error occurred: {e}", 500
        



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


#================================================================================================
#================================================================================================


# Xero Code
# Define the path to the file where tokens will be stored
TOKEN_FILE_PATH = 'xero_tokens2.txt'
RECORDS_FILE_PATH = 'records.txt'


def save_tokens(access_token, refresh_token, tenant_id):
    # Implement logic to save tokens securely (e.g., in a database or encrypted file)
    print("tenantID: ", tenant_id)
    with open(TOKEN_FILE_PATH, 'w') as f:
        f.write(f"access_token={access_token}\n")
        f.write(f"refresh_token={refresh_token}\n")
        f.write(f"tenant_id={tenant_id}\n")


def record_data(data):
    # Implement logic to save tokens securely (e.g., in a database or encrypted file)
    #print("tenantID: ", tenant_id)
    with open(RECORDS_FILE_PATH, 'w') as f:
        f.write(f"data={data}\n")
        

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
        "refresh_token": get_refresh_token()
    }
    response = requests.post(token_url, headers=headers, data=data)
    if response.status_code == 200:
        new_access_token = response.json().get("access_token")
        new_refresh_token = response.json().get("refresh_token")
        print(new_refresh_token)
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
#No tenant ID saved 
#Implement the create_invoice function to create an invoice in Xero
def create_invoice(xero_invoice, access_token, tenant_id):
    create_invoice_url = "https://api.xero.com/api.xro/2.0/Invoices"
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json",
        "xero-tenant-id": tenant_id
    }
    response = requests.post(create_invoice_url, headers=headers, json=xero_invoice)
    if response.status_code == 200:
        return "Invoice created successfully"
    else:
        error_message = f"Failed to create invoice: {response.text}"
        print(error_message)
        return error_message

# Define the home route    
@app.route('/')
def home():
    print("request args: ", request.args)
    return "Welcome to the Invoice Creation App!!"

# Define the login route to start the OAuth 2.0 flow
@app.route('/login')
def login():
    # Redirect the user to the Xero authorization URL (same as before)
    xero_authorization_url = (
        "https://login.xero.com/identity/connect/authorize?"
        f"response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        "&scope=openid offline_access profile email accounting.transactions&state=123"
    )
    print("xero_authorization_url: ", xero_authorization_url)
    return redirect(xero_authorization_url)

# Define the callback route to handle the authorization code automatically
@app.route('/callback')
def callback():
    # Get the authorization code from the query parameters
    code = request.args.get('code')
    print("request args: ", request.args)
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
    response = requests.post(token_url, headers=headers, data=data)
    print("response: ", response.json())
    # Handle the response
    if response.status_code == 200:
        access_token = response.json().get("access_token")
        refresh_token = response.json().get("refresh_token")
        tenant_id = check_tenants(access_token)
        save_tokens(access_token, refresh_token, tenant_id)
        
        return "Authorization successful. You can now create invoices."
    else:
        return "Failed to exchange the authorization code for an access token. Response Error: " + response.text


def check_tenants(access_t):
    t_response = requests.get("https://api.xero.com/connections", headers={"Authorization": "Bearer " + access_t, "Content-Type": "application/json"})
    print("tenants: ", t_response.json())
    #GET https://api.xero.com/connections
#Authorization: "Bearer " + access_token
#Content-Type: application/json
    
    response_data = t_response.json()
    record_data(response_data)

# Iterate over the list to find the dictionary with 'tenantName' as 'Book Express Ltd'
    for item in response_data:
        if item['tenantName'] == 'Book Express Ltd':
            tenant_id_demo = item['tenantId']
            print("Demo ID: ", tenant_id_demo)
            return tenant_id_demo
    return None

# Define the create_invoice route to create an invoice in Xero once authorized
#@app.route('/create_invoice')
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



# Process Emails
def process_fishpond(text):
    name_pattern = r"Send to:\s*\n\n(\w+ \w+)"
    email_pattern = r"(\w+@\w+\.\w+)"
    phone_pattern = r"(\+\d{2} \d{2} \d{6})"
    address_patterns = {
        'AddressLine1': r"Send to:\s*[\s\S]*?\n\n.*\n(.*?)\n",
        'AddressLine2': r"Send to:\s*[\s\S]*?\n\n.*\n.*\n(.*?)\n",
        'AddressLine3': r"Send to:\s*[\s\S]*?\n\n.*\n.*\n.*\n(.*?)\n",
        'City': r"Send to:\s*[\s\S]*?\n\n.*\n.*\n.*\n.*\n(\D+),",
        'PostalCode': r"Send to:\s*[\s\S]*?\n\n.*\n.*\n.*\n.*\n.*,\s*(\d+)"
    }

    total_pattern = r"=\s*\$(\d+\.\d{2})"

    extracted_address = {}
    for key, pattern in address_patterns.items():
        match = re.search(pattern, text)
        if match:
            extracted_address[key] = match.group(1).strip()

    name_match = re.search(name_pattern, text)
    email_match = re.search(email_pattern, text)
    phone_match = re.search(phone_pattern, text)
    total_match = re.search(total_pattern, text)
    Name = name_match.group(1)
    EmailAddress = email_match.group(1)
    Phone = phone_match.group(1)
    Total = total_match.group(1)

    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        # Proceed with invoice creation using the refreshed access token
        tenant_id = get_tenant_id()

        #contact = Contact(ContactID=-1, Name=name, EmailAddress=email_address, Phone=phone)
        #contact.add_address(AddressType="STREET", AddressLine1=address_line1,AddressLine2 = address_line2,AddressLine3='', City=city, PostalCode=postal_code)

        # Replace this example invoice data with your actual data
        xero_invoice = {
            "Type": "ACCREC",
            "Contact": {
                "Name": Name,
                "Addresses": [{
                    "AddressType": "STREET",
                    "AddressLine1": address_line1,
                    "AddressLine2": address_line2,
                    "City": city,
                    "PostalCode": postal_code
                }]
            },
            "Date": "2023-01-01",
            "DueDate": "2023-01-15",
            "LineItems": [{
                "Description": "Example Item",
                "Quantity": 1,
                "UnitAmount": Total,
                "AccountCode": "220"
            }], 
            "Reference": "Chrisland Sale"
        }
        result = create_invoice(xero_invoice, access_token, tenant_id)

    # erase the contents of the messages.txt file
    open('messages.txt', 'w').close()



    #contact = Contact(ContactID=-1, Name=Name, EmailAddress=EmailAddress, Phone=Phone)
    #contact.add_address(AddressType="STREET", AddressLine1=extracted_address.get('AddressLine1'),AddressLine2 = extracted_address.get('AddressLine2'),AddressLine3 = extracted_address.get('AddressLine3'), City=extracted_address.get('City'), PostalCode=extracted_address.get('PostalCode'))
    #print(contact)
    #invoice = Invoice(contact=contact, sub_total='', total=Total, currency_code="NZD", invoice_id="123", invoice_number="INV123")
    #print(invoice)

def process_christland(text):
    print(" ")
    name_pattern = r"Shipping Info\n\n(.+)"
    address_line1_pattern = r"Shipping Info\n\n.+\n\n(.+)"
    address_line2_pattern = r"Shipping Info\n\n.+\n\n.+\n\n(.+)"
    city_pattern = r"Shipping Info\n\n.+\n\n.+\n\n.+\n\n(.+)"
    email_pattern = r"(\S+@\S+)"
    phone_pattern = r"Phone: (\d+)"
    subtotal_pattern = r"Subtotal\s+NZ\$(\d+\.\d{2})"
    total_pattern = r"Total\s+NZ\$(\d+\.\d{2})"

    name = re.search(name_pattern, text).group(1)
    address_line1 = re.search(address_line1_pattern, text).group(1)
    address_line2 = re.search(address_line2_pattern, text).group(1)
    cityText = re.search(city_pattern, text).group(1)
    city, postal_code = cityText.split(" ", 1)
    email_address = re.search(email_pattern, text).group(1)
    phone = re.search(phone_pattern, text).group(1)

    subtotal_match = re.search(subtotal_pattern, text)
    sub_total = subtotal_match.group(1)
    
    total_match = re.search(total_pattern, text)
    total = total_match.group(1)

    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        # Proceed with invoice creation using the refreshed access token
        tenant_id = get_tenant_id()

        #contact = Contact(ContactID=-1, Name=name, EmailAddress=email_address, Phone=phone)
        #contact.add_address(AddressType="STREET", AddressLine1=address_line1,AddressLine2 = address_line2,AddressLine3='', City=city, PostalCode=postal_code)

        # Replace this example invoice data with your actual data
        xero_invoice = {
            "Type": "ACCREC",
            "Contact": {
                "Name": name,
                "Addresses": [{
                    "AddressType": "STREET",
                    "AddressLine1": address_line1,
                    "AddressLine2": address_line2,
                    "City": city,
                    "PostalCode": postal_code
                }]
            },
            "Date": "2023-01-01",
            "DueDate": "2023-01-15",
            "LineItems": [{
                "Description": "Example Item",
                "Quantity": 1,
                "UnitAmount": total,
                "AccountCode": "220"
            }], 
            "Reference": "Chrisland Sale"
        }
        result = create_invoice(xero_invoice, access_token, tenant_id)
        # erase the contents of the messages.txt file
        open('messages.txt', 'w').close()
    
    #print(contact)
    #invoice = Invoice(contact=contact, sub_total=sub_total, total=total, currency_code="NZD", invoice_id="123", invoice_number="INV123")
    #print(invoice)
   

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

    AddressLine2 = None
    if len(lines) > ship_to_index + 2:
        AddressLine2 = lines[ship_to_index + 2].strip()
        if AddressLine2 == City+" "+PostalCode :
            AddressLine2 = ""


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
                "Name": Name,
                "Addresses": [{
                    "AddressType": "STREET",
                    "AddressLine1": AddressLine1,
                    "AddressLine2": AddressLine2,
                    "City": City,
                    "PostalCode": PostalCode
                }]
            },
            "Date": "2023-01-01",
            "DueDate": "2023-01-15",
            "LineItems": [{
                "Description": "Example Item",
                "Quantity": 1,
                "UnitAmount": total,
                "AccountCode": "200"
            }], 
            "Reference": "Biblio Sale"
        }
        result = create_invoice(xero_invoice, access_token, tenant_id)
        # erase the contents of the messages.txt file
        open('messages.txt', 'w').close()

        print(result)
        return result

    #contact = Contact(ContactID=-1, Name=Name, EmailAddress=EmailAddress, Phone=Phone)
    #contact.add_address(AddressType="STREET", AddressLine1=AddressLine1, AddressLine2=AddressLine2,AddressLine3='', City=City, PostalCode=PostalCode)
    #print(contact)  

    # call Xero api, send contact and get the contact_id
    
    #invoice = Invoice(contact=contact, sub_total=sub_total, total=total, currency_code="NZD", invoice_id="123", invoice_number="INV123")
    #print(invoice)
    
def finding_source(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            if 'Biblio.co.nz' in content:
                print('this is a mail from + Biblio.co.nz')
                return process_biblio(content)
            elif 'Fishpond.co.nz' in content:
                print("this is a mail from fishpond")
                return process_fishpond(content)
            else:
                print("this is a mail from christland")
                return process_christland(content)

    except FileNotFoundError:
        return "file not found"


@app.route('/testInvoiceFromFile')
def testInvoiceFromFile():
    file_path = 'messages.txt'
    result = finding_source(file_path)