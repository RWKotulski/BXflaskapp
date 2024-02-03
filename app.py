from flask import Flask, request
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

app = Flask(__name__)

app.logger.setLevel(logging.INFO)

if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)
    



# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

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
        


@app.route('/')
def index():
    app.logger.info(f'Info Log')
    app.logger.error("Error Log")
    return "Hello World!"


@app.route('/')
def hello():
    """Renders a sample page."""
    return "Hello World!"

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

"""
@app.route('/append-message', methods=['POST'])
def append_message():

    if request.is_json:
        try:
            data = request.get_json()
            message = data.get('text', '')
            # Specify the file path
            file_path = 'messages.txt'
            # Open the file and append the message
            with open(file_path, 'a') as file:
                file.write(message + '\n')
                return "Message appended to file", 200
        except Exception as e:
            # Handle exceptions
            return f"An error occurred: {e}", 500
    else: 
        app.logger.info(request.data)
        return "Request body must be JSON", 400
"""

if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)  # Enable debug mode for easier development
    print(f"This is running on port {PORT}")