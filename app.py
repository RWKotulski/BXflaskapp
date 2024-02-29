from flask import Flask, json, request, redirect, url_for
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import csv
import base64
import sendgrid
from sendgrid.helpers.mail import Mail, Email, To, Content
from flask import Flask
import requests
import base64
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)




if __name__ == "__main__":
    file_path = 'messages.txt'
   
#   sales@bxpoc.richardbaldwin.nz

# Define your Xero API credentials and redirect URI
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = "https://bx.richardbaldwin.nz/callback"

# Set up logging for debugging
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
    return "Hello World!"

@app.route('/append-message', methods=['POST'])
def handle_request():
    try:
        record_data("HR Called")
        # Convert form data to a dictionary
        form_data = request.form.to_dict()
        
        # Specify the file path
        file_path = 'messages.txt'
        
        # Serialize form_data to a JSON string with indentation for readability
        form_data_json = json.dumps(form_data, indent=4)
        
        # Open the file and append the serialized form data
        record_data("About to record data HRRRRRRRRR") 
        with open(file_path, 'w') as file:
            file.write(form_data_json + '\n')
            record_data("Data Written")
            
        check_and_process()
        finding_source(file_path)
        record_data("After find")
        
        return "Form data appended to file", 200
    except Exception as e:
        # Handle exceptions
        record_data(f"An error occurred: {e}") 
        return f"An error occurred: {e}", 500


    
# Working Test Email Code

def send_email():
    sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
    from_email = Email("richard@monument.page")  # Change to your verified sender
    to_email = To("richard@empyre.co")  # Change to your recipient
    subject = "Update Refesh Token"
    content = Content("text/plain", "Here is the refesh link, please login to update the token: https://bx.richardbaldwin.nz/login")
    mail = Mail(from_email, to_email, subject, content)

    # Get a JSON-ready representation of the Mail object
    mail_json = mail.get()

    # Send an HTTP POST request to /mail/send
    response = sg.client.mail.send.post(request_body=mail_json)

    # This is the response from the SendGrid API, but it's not strictly required
    #print(response.status_code)
    #print(response.headers)


def check_and_process():
    date_file_path = 'last_date.txt'  # Path to the file storing the last date
    try:
        # Check if the date file exists and read the last date
        if os.path.exists(date_file_path):
            with open(date_file_path, 'r') as file:
                last_date_str = file.read().strip()
                last_date = datetime.strptime(last_date_str, "%Y-%m-%d")
        else:
            last_date = datetime.now() - timedelta(days=51)  # Default to a date ensuring the condition is met if file doesn't exist
        
        # Calculate if 50 days have passed
        if (datetime.now() - last_date).days >= 50:
            send_email()  # Call the function to send an email
            # Update the last date in the file
            with open(date_file_path, 'w') as file:
                file.write(datetime.now().strftime("%Y-%m-%d"))
            record_data("Email sent and date updated.")
            return "Email sent and date updated.", 200
        else:
            record_data("It has not been 50 days yet.")
            return "It has not been 50 days yet.", 200
    except Exception as e:
        record_data("Error check_and_process")
        return f"An error occurred: {e}", 500

#================================================================================================
    #Xero Code
#================================================================================================



# Define the path to the file where tokens will be stored
TOKEN_FILE_PATH = 'xero_tokens2.txt'
RECORDS_FILE_PATH = 'records.txt'

# Saves tokens to a file
def save_tokens(access_token, refresh_token, tenant_id):
    print("tenantID: ", tenant_id)
    with open(TOKEN_FILE_PATH, 'w') as f:
        f.write(f"access_token={access_token}\n")
        f.write(f"refresh_token={refresh_token}\n")
        f.write(f"tenant_id={tenant_id}\n")

# Records Data in a file
def record_data(data):

    with open(RECORDS_FILE_PATH, 'a') as f:
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
        record_data("Invoice Success")
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


#================================================================================================
    #Process the Emails
#================================================================================================

def process_fishpond(file_path):
    record_data("Fishponds Pro v5.3")

    def safe_search(pattern, text, group=1):
        matches = re.findall(pattern, text)
        if matches:
            return matches[1] if len(matches) > 1 else None
        return None

    with open(file_path, 'r') as file:
        data = json.load(file)
    
    text = data.get('text', '')

    # Updated pattern to capture the entire address block more accurately
    address_block_pattern = r"Send to:\s*\r?\n\r?\n(.+?)\s*\r?\n(.+?)\s*\r?\n(.+?)\s*\r?\n(.+?)\s*\r?\n(.+), (\d{4})\s*\r?\n(.+)"
    total_sale_pattern = r"\(\$[\d.]+ \+ \$[\d.]+\)\*[\d.]+ = \$(\d+\.\d{2})"

    match = re.search(address_block_pattern, text, re.DOTALL)
    total_sale_match = re.search(total_sale_pattern, text)
    
    if match:
        extracted_data = {
            'name': match.group(2),  # Corrected to capture the name properly
            'address_line1': match.group(3),  # First address line
            'address_line2': match.group(4),  # Second address line (Suburb)
            'city': match.group(5),  # Correctly capturing the city name
            'postal_code': match.group(6),  # Postal code
            'country': match.group(7),  # Country
            'total': total_sale_match.group(1) if total_sale_match else "Total not found",
        }
    else:
        extracted_data = {}

    record_data("Extracted Data:")
    for key, value in extracted_data.items():
        record_data(f"{key}: {value}")

    record_data("Starting Invoice Creation")
    if None not in [extracted_data.get('name'), extracted_data.get('address_line1'), extracted_data.get('city'), extracted_data.get('postal_code'), extracted_data.get('total')]:
        record_data("Inside IF (Fish)")    
        xero_invoice = format_to_json(
            extracted_data.get('name'), 
            extracted_data.get('address_line1'), 
            extracted_data.get('address_line2'), 
            extracted_data.get('city'), 
            extracted_data.get('postal_code'), 
            extracted_data.get('total'), 
            "Fishpond Sale"
        )
        record_data("Invoice:")
        record_data(xero_invoice)
        access_token = refresh_access_token()
        if access_token is None:
            access_token = refresh_access_token()
        if access_token:
            record_data("Xero Invoice v1")    
            tenant_id = get_tenant_id()
            
            result = create_invoice(xero_invoice, access_token, tenant_id)
            # erase the contents of the messages.txt file
            #open('messages.txt', 'w').close()
            return result
        else:
            record_data("Failed to create invoice. Unable to obtain access token.")
            return "Failed to create invoice. Unable to obtain access token."
    else:
        record_data("Missing required data for invoice creation.")


'''
# Process Fishpond Emails to extract the relevant data
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

    data=['fishpond','null',Name,EmailAddress,Total]
    save_to_csv(data)

    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        tenant_id = get_tenant_id()
        xero_invoice = format_to_json(Name, extracted_address.get('AddressLine1'), extracted_address.get('AddressLine2'), extracted_address.get('City'), extracted_address.get('PostalCode'), Total, "Fishpond Sale")
        result = create_invoice(xero_invoice, access_token, tenant_id)
        # erase the contents of the messages.txt file
        open('messages.txt', 'w').close()
        return result
    else:
        return "Failed to create invoice. Unable to obtain access token."
'''

def process_christland(file_path):
    record_data("Chrissy Pro v6.1")    

    # Load and parse the JSON file
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    text = data.get('text', '')

    # Adjusted regex patterns to match both \r\n (Windows) and \n (Unix) line breaks
    orderid_pattern = r"\*Order ID: \*(\d+)"
    name_pattern = r"Shipping Info\r?\n\r?\n(.+)"
    address_line1_pattern = r"Shipping Info\r?\n\r?\n.+\r?\n\r?\n(.+)"
    address_line2_pattern = r"Shipping Info\r?\n\r?\n.+\r?\n\r?\n.+\r?\n\r?\n(.+)"
    # Updated city and postal code pattern
    city_postal_pattern = r"Shipping Info\r?\n\r?\n.+\r?\n\r?\n.+\r?\n\r?\n.+?\r?\n\r?\n(.+?)\s+(\d{4})\r?\n"
    email_pattern = r"(\S+@\S+)"
    phone_pattern = r"Phone: (\d+)"
    subtotal_pattern = r"Subtotal\s+NZ\$(\d+\.\d{2})"
    total_pattern = r"Total\s+NZ\$(\d+\.\d{2})"

    extracted_data = {}

    def safe_search(pattern, text, group=1):
        match = re.search(pattern, text)
        if match:
            return match.group(group) if group else match.groups()
        return None

    # Extract data using defined patterns
    extracted_data['order_id'] = safe_search(orderid_pattern, text)
    extracted_data['name'] = safe_search(name_pattern, text)
    extracted_data['address_line1'] = safe_search(address_line1_pattern, text)
    extracted_data['address_line2'] = safe_search(address_line2_pattern, text)
    
    # Extract city and postal code together
    city_postal_match = safe_search(city_postal_pattern, text, group=None)
    if city_postal_match:
        extracted_data['city'], extracted_data['postal_code'] = city_postal_match
    
    extracted_data['email_address'] = safe_search(email_pattern, text)
    extracted_data['phone'] = safe_search(phone_pattern, text)
    extracted_data['sub_total'] = safe_search(subtotal_pattern, text)
    extracted_data['total'] = safe_search(total_pattern, text)

    record_data("Extracted Data:")
    for key, value in extracted_data.items():
        record_data(f"{key}: {value}")
        
    record_data("Starting Invoice Creation")
    if None not in [extracted_data.get('name'), extracted_data.get('address_line1'), extracted_data.get('city'), extracted_data.get('postal_code'), extracted_data.get('total')]:
        record_data("Inside IF")    
        xero_invoice = format_to_json(
            extracted_data.get('name'), 
            extracted_data.get('address_line1'), 
            extracted_data.get('address_line2'), 
            extracted_data.get('city'), 
            extracted_data.get('postal_code'), 
            extracted_data.get('total'), 
            "Chrisland Sale"
        )
        record_data("Invoice:")
        record_data(xero_invoice)
        access_token = refresh_access_token()
        if access_token is None:
            access_token = refresh_access_token()
        if access_token:
            record_data("Xero Invoice v1")    
            tenant_id = get_tenant_id()
            
            result = create_invoice(xero_invoice, access_token, tenant_id)
            # erase the contents of the messages.txt file
            open('messages.txt', 'w').close()
            return result
        else:
            return "Failed to create invoice. Unable to obtain access token."
    else:
        record_data("Missing required data for invoice creation.")
    
    

    
    # Assuming format_to_json and other functions handle None values appropriately
    # xero_invoice = format_to_json(...) would go here, but omitted for brevity

# Example file_path usage, assuming the function is called with the correct file path
# process_christland('/path/to/your/file.json')


'''
# Process Chrisland Emails to extract the relevant data
def process_christland_old(text):
    record_data("process called v1")
    orderid_pattern = r"\*Order ID: \*(\d+)"
    name_pattern = r"Shipping Info\n\n(.+)"
    address_line1_pattern = r"Shipping Info\n\n.+\n\n(.+)"
    address_line2_pattern = r"Shipping Info\n\n.+\n\n.+\n\n(.+)"
    city_pattern = r"Shipping Info\n\n.+\n\n.+\n\n.+\n\n(.+)"
    email_pattern = r"(\S+@\S+)"
    phone_pattern = r"Phone: (\d+)"
    subtotal_pattern = r"Subtotal\s+NZ\$(\d+\.\d{2})"
    total_pattern = r"Total\s+NZ\$(\d+\.\d{2})"
    order_id = re.search(orderid_pattern, text).group(1)
    name = re.search(name_pattern, text).group(1)
    address_line1 = re.search(address_line1_pattern, text).group(1)
    address_line2 = re.search(address_line2_pattern, text).group(1)
    cityText = re.search(city_pattern, text).group(1)
    city, postal_code = cityText.split(" ", 1)
    email_address = re.search(email_pattern, text).group(1)
    phone = re.search(phone_pattern, text).group(1)
    subtotal_match = re.search(subtotal_pattern, text)
    sub_total = subtotal_match.group(1)
    record_data("Made through match groups")
   
    total_match = re.search(total_pattern, text)
    total = total_match.group(1)
    
    xero_invoice = format_to_json(name, address_line1, address_line2, city, postal_code, total, "Chrisland Sale")
    record_data("Invoice:")
    record_data(xero_invoice)
    
    data = ['chrisland',order_id,name,email_address,total]
    save_to_csv(data)

    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        tenant_id = get_tenant_id()
        xero_invoice = format_to_json(name, address_line1, address_line2, city, postal_code, total, "Chrisland Sale")
        result = create_invoice(xero_invoice, access_token, tenant_id)
        # erase the contents of the messages.txt file
        open('messages.txt', 'w').close()
        return result
    else:
        return "Failed to create invoice. Unable to obtain access token."
    '''    

def process_biblio(file_path):
    record_data("Biblio Pro v1.7")

    with open(file_path, 'r') as file:
        data = json.load(file)
    
    text = data.get('text', '')

    # Adjusted regex patterns
    ship_to_pattern = r"Ship to:\*?\r?\n(.+)\r?\n(.+)\r?\n(.+)\r?\n(.+) , (.+) (\d{4})"
    total_sale_pattern = r"Total: NZ\$(\d+\.\d{2})"
    
    extracted_data = {}
    
    def safe_search(pattern, text):
        match = re.search(pattern, text)
        if match:
            return match.groups()
        return None
    
    extracted_data['total'] = safe_search(total_sale_pattern, text)[0] if safe_search(total_sale_pattern, text) else "Total not found"
    ship_to_match = safe_search(ship_to_pattern, text)
    if ship_to_match:
        extracted_data['ship_to_name'] = ship_to_match[0].strip()  # Removes trailing carriage return
        extracted_data['street'] = ship_to_match[1].strip()
        extracted_data['suburb'] = ship_to_match[2].strip()
        extracted_data['city'] = ship_to_match[3].strip()
        extracted_data['postal_code'] = ship_to_match[5].strip()

    # Update the rest of your data extraction and processing as needed

    record_data("Extracted Data:")
    for key, value in extracted_data.items():
        record_data(f"{key}: {value}")
    

    record_data("Starting Invoice Creation")
    if None not in [extracted_data.get('ship_to_name'), extracted_data.get('street'),extracted_data.get('suburb'), extracted_data.get('city'), extracted_data.get('postal_code'), extracted_data.get('total')]:
        record_data("Inside IF (Bib)")     
        xero_invoice = format_to_json(
            extracted_data.get('ship_to_name'), 
            extracted_data.get('street'), 
            extracted_data.get('suburb'), 
            extracted_data.get('city'), 
            extracted_data.get('postal_code'), 
            extracted_data.get('total'), 
            "Biblio Sale"
        )
        record_data("Invoice:")
        record_data(xero_invoice)
        access_token = refresh_access_token()
        if access_token is None:
            access_token = refresh_access_token()
        if access_token:
            record_data("Xero Invoice v1")    
            tenant_id = get_tenant_id()
            
            result = create_invoice(xero_invoice, access_token, tenant_id)
            # erase the contents of the messages.txt file
            open('messages.txt', 'w').close()
            return result
        else:
            return "Failed to create invoice. Unable to obtain access token."
    else:
        record_data("Missing required data for invoice creation.")

'''
# Process Biblio Emails to extract the relevant data
def process_biblio(text):
    email_match = re.search(r"\*Customer Email: \*.*<(.+?)>", text)
    phone_match = re.search(r"\*Customer Phone: \*([0-9 ]+)", text)

    # get order_id
    id_pattern = r"Shipment\s*#\s*([0-9]+-[0-9]+-[0-9]+)"
    id_match = re.search(id_pattern, text)
    order_id = id_match.group(1)
    print("Order ID:", order_id)

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

    data = ['biblio',order_id,Name,EmailAddress,str(total)]
    #save_to_csv(data)

    access_token = get_access_token()
    if access_token is None:
        access_token = refresh_access_token()
    if access_token:
        tenant_id = get_tenant_id()
        xero_invoice = format_to_json(Name, AddressLine1, AddressLine2, City, PostalCode, total, "Biblio Sale")
        result = create_invoice(xero_invoice, access_token, tenant_id)
        # erase the contents of the messages.txt file
        open('messages.txt', 'w').close()

        return result
    else:
        return "Failed to create invoice. Unable to obtain access token."
'''

# Process the file to determine the source of the email
def finding_source(file_path):
    record_data("Finding Source Called")
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            if 'Biblio.co.nz' in content:
                record_data('this is a mail from + Biblio.co')
                return process_biblio(file_path)
            elif 'Fishpond' in content:
                record_data("this is a mail from fishpond")
                return process_fishpond(file_path)
            elif 'chrislands' in content:
                record_data("this is a mail from chrisland")
                return process_christland(file_path)
            else :
                record_data("unidentified source")
    except FileNotFoundError:
        record_data("File reading error (finding_source)")
        return "file not found"


# Test the invoice creation from a file
@app.route('/testInvoiceFromFile')
def testInvoiceFromFile():
    record_data("testInvoiceFromFile called")
    file_path = 'bib_test.txt'
    result = finding_source(file_path)
    return result
   
   
# creates a Xero invoice object from the data
def format_to_json(name1, address_line11, address_line21, city1, postal_code1, total1, sale_ref1):
    record_data("To Json Called v1.4")
    due_in_days = 1
    auckland_timezone = pytz.timezone('Pacific/Auckland')
    current_date = datetime.now(auckland_timezone).strftime("%Y-%m-%d")

    due_date = (datetime.now(auckland_timezone) + timedelta(days=due_in_days)).strftime("%Y-%m-%d")
    xero_invoice = {
            "Type": "ACCREC",
            "Contact": {
                "Name": name1,
                "Addresses": [{
                    "AddressType": "STREET",
                    "AddressLine1": address_line11,
                    "AddressLine2": address_line21,
                    "City": city1,
                    "PostalCode": postal_code1
                }]
            },
            "Status": "DRAFT", #https://developer.xero.com/documentation/api/accounting/types#invoicess
            "Date": current_date,
            "DueDate": due_date,
            "LineItems": [{
                "Description": "Example Item",
                "Quantity": 1,
                "UnitAmount": total1,
                "AccountCode": "220"
            }],
            "Reference": sale_ref1
        }
    record_data("To Json finished")    
    return xero_invoice