from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt 
from flask_mysqldb import MySQL
from scapy.all import *
import re 
import os
from flask import current_app as app
from flask import jsonify
from flask import session
from flask_session import Session
import csv
import matplotlib.pyplot as plt
import io
import base64
from flask import render_template, Response
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from mac_vendor_lookup import MacLookup, VendorNotFoundError

app = Flask(__name__)




 # Use filesystem for server-side session storage
app.config['SESSION_TYPE'] = 'filesystem' 
app.config['SECRET_KEY'] = 'myFlaskNetCanvasApp' 
Session(app) 
# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'netcanvas'
app.secret_key = 'myFlaskNetCanvasApp'

mysql = MySQL(app)

# Function to seed initial admin data
def seed_admin():
    cursor = mysql.connection.cursor()
    email = 'awais@gmail.com'
    cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
    admin = cursor.fetchone()
    if admin is None:
        hashed_password = bcrypt.hashpw('@M.awais'.encode('utf-8'), bcrypt.gensalt())
        license_key = 'A052-L140-H142'  
        cursor.execute("INSERT INTO admin (name, email, password, license_key) VALUES (%s, %s, %s, %s)", ('Awais', email, hashed_password, license_key))
        mysql.connection.commit()
        print('Initial admin registered successfully!')
    else:
        print('Admin already exists in the database!')
    cursor.close()


#  call seed_admin()
with app.app_context():
    seed_admin()

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin where email=%s", (field.data,))
        admin = cursor.fetchone()
        cursor.close()
        if admin:
            raise ValidationError('Email Already Taken')
    

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
    
class AdminLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    license_key = StringField("License Key", validators=[DataRequired()])
    submit = SubmitField("Login")


def password_checks(password):
    
    if len(password) < 8:
        return "Password contain at least 8 characters"
    if not any(char.isupper() for char in password):
        return "Password msut contain one Upper case character"
    if not re.search(r'[!@#$%^&*(),.?:{}<>|]',password):
        return "Password must contain one special character"
    else:
        return "Password is Valid"
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        
        if user:
            # Calculate network state
            total_packets, unique_source_ips, unique_destination_ips, total_nodes = calculate_network_state()
            
            # Calculate unique IP counts
            total_source_ips, total_destination_ips = count_unique_ips()
            
            # Calculate total assets count
            total_assets = total_source_ips + total_destination_ips
            
            return render_template('dashboard.html', user=user,
                                   total_packets=total_packets,
                                   unique_source_ips=unique_source_ips,
                                   unique_destination_ips=unique_destination_ips,
                                   total_nodes=total_nodes,
                                   total_assets=total_assets)
    return redirect(url_for('login'))




@app.route('/asset_discovery')
def asset_discovery():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if request.method == 'POST':
            # Handle POST method here if needed
            return render_template('asset_discovery_result.html', user=user)
        else:
            # Handle GET method here
            packets = []
            try:
                with open('captured_packets.csv', 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        # Fetch only source and destination IP addresses along with their vendors
                       packets.append({
    'source_mac': row['source_mac'],
    'destination_mac': row['destination_mac'],
    'source_vendor': row['source_vendor'],
    'destination_vendor': row['destination_vendor'],
    'asset_type': row['asset_type']
})
            except FileNotFoundError:
                print("The file does not exist yet.")
            return render_template('asset_discovery.html', user=user, packets=packets)
    else:
        return redirect(url_for('login'))

@app.route('/visualization')
def visualization():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()
        print(user)

       
    nodes = []  # List to store all nodes
    links = []  # List to store all links

    # Read data from CSV file and process each row
    with open('captured_packets.csv', 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            source_ip = row['source_ip']
            destination_ip = row['destination_ip']

            # Add source and destination nodes to the list of nodes
            nodes.append({'id': source_ip, 'type': 'source'})
            nodes.append({'id': destination_ip, 'type': 'destination'})

            # Add links between source and destination nodes
            links.append({'source': source_ip, 'target': destination_ip})

    if user:
        return render_template('visualization.html', nodes=nodes, links=links,user=user)



@app.route('/network_state')
def network_state():
    # Read data from captured_packets.csv
    with open('captured_packets.csv', 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        packets = list(reader)

    # Calculate network state
    total_packets = len(packets)
    unique_source_ips = len(set(packet['source_ip'] for packet in packets))
    unique_destination_ips = len(set(packet['destination_ip'] for packet in packets))

    # Create a bar plot
    categories = ['Total Packets', 'Unique Source IPs', 'Unique Destination IPs']
    values = [total_packets, unique_source_ips, unique_destination_ips]

    plt.figure(figsize=(8, 6))
    plt.bar(categories, values, color='blue')
    plt.title('Network State Statistics')
    plt.xlabel('Category')
    plt.ylabel('Count')
    plt.grid(axis='y')

    # Convert plot to a PNG image in memory
    image_stream = io.BytesIO()
    plt.savefig(image_stream, format='png')
    image_stream.seek(0)
    plot_image = base64.b64encode(image_stream.getvalue()).decode()

    # Pass statistics data and plot image to the HTML template
    return render_template('network_state.html', total_packets=total_packets,
                           unique_source_ips=unique_source_ips,
                           unique_destination_ips=unique_destination_ips,
                           plot_image=plot_image)
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('index_page'))

@app.route('/index')
def index_page():
    return render_template('index.html')
   
@app.route('/admin')
def admin_index():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password",'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


def classify_asset(packet):
        # Extract relevant information from the packet
        source_ip = packet['source_ip']
        destination_ip = packet['destination_ip']
        protocol = packet['protocol']
        packet_length = packet['packet_length']
        source_mac = packet['source_mac']
        destination_mac = packet['destination_mac']
        
        # Perform classification based on criteria
        if protocol == 'TCP':
            if destination_ip == '192.168.1.1':  # Example IP address for a server
                return 'Server'
            elif packet_length > 1000:
                return 'Data Server'
            elif source_ip.startswith('192.168.1'):  # Example IP range for internal network
                return 'Internal TCP'
            else:
                return 'External TCP'
        elif protocol == 'UDP':
            if source_mac.startswith('00:11:22'):
                return 'IoT Device'
            elif destination_ip.startswith('224.0.0'):  # Example multicast IP range
                return 'Multicast UDP'
            else:
                return 'Unknown UDP'
        elif protocol == 'ICMP':
            return 'ICMP Protocol'
        elif protocol == 'ARP':
            return 'ARP Protocol'
        elif protocol == 'DNS':
            return 'DNS Protocol'
        elif protocol == 'HTTP':
            return 'HTTP Protocol'
        elif protocol == 'HTTPS':
            return 'HTTPS Protocol'
        elif protocol == 'FTP':
            return 'FTP Protocol'
        else:
            return 'Unknown Protocol'


# Modify your packet processing function to include asset classification
def read_packets(path):
    packets = []
    pcap_file = path
    session.pop('captured_packets', None)

    # Instantiate MacLookup object
    mac_lookup = MacLookup()

    try:
        pkts = rdpcap(pcap_file)
        i = 0
        for packet in pkts:
            i += 1
            packet_details = {
                'source_ip': packet[IP].src if IP in packet else None,
                'destination_ip': packet[IP].dst if IP in packet else None,
                'protocol': packet[IP].proto if IP in packet else None,
                'packet_length': len(packet),
                'packet_info': repr(packet),
                'source_mac': packet[Ether].src if Ether in packet else None,
                'destination_mac': packet[Ether].dst if Ether in packet else None,
                'source_vendor': None,
                'destination_vendor': None,
                'sr': i
            }

            # Classify asset based on behavior
            packet_details['asset_type'] = classify_asset(packet_details)

            # Look up vendor for source MAC address
            if 'source_mac' in packet_details and packet_details['source_mac']:
                try:
                    packet_details['source_vendor'] = mac_lookup.lookup(packet_details['source_mac'])
                except VendorNotFoundError:
                    packet_details['source_vendor'] = 'Vendor Not Found'

            # Look up vendor for destination MAC address
            if 'destination_mac' in packet_details and packet_details['destination_mac']:
                try:
                    packet_details['destination_vendor'] = mac_lookup.lookup(packet_details['destination_mac'])
                except VendorNotFoundError:
                    packet_details['destination_vendor'] = 'Vendor Not Found'
   # Classify asset based on packet behavior
            packet_details['asset_type'] = classify_asset(packet_details)
            packets.append(packet_details)
    except Exception as e:
        print(f"An error occurred while processing packets: {e}")

    return packets


@app.route('/start_capture', methods=['GET', 'POST'])
def start_capture():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s",(user_id,))
        user = cursor.fetchone()
        cursor.close()
         
        if request.method == 'POST':
            pcapFile = request.files['pcap_file']
            if pcapFile:
                captured_packets = read_packets(pcapFile)
                
                # Add the 'sr' field to each packet
                for i, packet in enumerate(captured_packets, start=1):
                    packet['sr'] = i
                
                # Instantiate MacLookup object
                mac_lookup = MacLookup()
                
                # Write captured packets to CSV file
                csv_filename = 'captured_packets.csv'
                with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['sr', 'source_ip', 'destination_ip', 'protocol', 'packet_length', 'packet_info', 'source_mac', 'destination_mac', 'source_vendor', 'destination_vendor','asset_type']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for packet in captured_packets:
                        # Lookup vendors for source and destination MAC addresses
                        try:
                            source_vendor = mac_lookup.lookup(packet['source_mac']) if packet['source_mac'] else 'Vendor Not Found'
                        except VendorNotFoundError:
                            source_vendor = 'Vendor Not Found'
                            
                        try:
                            destination_vendor = mac_lookup.lookup(packet['destination_mac']) if packet['destination_mac'] else 'Vendor Not Found'
                        except VendorNotFoundError:
                            destination_vendor = 'Vendor Not Found'
                        
                        # Classify asset based on packet behavior
                        asset_type = classify_asset(packet)
                        
                        # Write packet details to CSV file
                        writer.writerow({
                            'sr': packet['sr'],  # Include sr field
                            'source_ip': packet['source_ip'],
                            'destination_ip': packet['destination_ip'],
                            'protocol': packet['protocol'],
                            'packet_length': packet['packet_length'],
                            'packet_info': packet['packet_info'],
                            'source_mac': packet['source_mac'],
                            'destination_mac': packet['destination_mac'],
                            'source_vendor': source_vendor,
                            'destination_vendor': destination_vendor,
                            'asset_type': asset_type  # Include asset_type
                        })
                    
                flash("Packets captured and saved successfully!", 'success')
                session['captured_packets'] = captured_packets  
                return render_template('captured_packets.html', user=user, packets=captured_packets)
            else:
                flash('PCAP FILE NOT FOUND', 'danger')
                return redirect(url_for('start_capture'))
        else:
            return render_template('captured_packets.html', user=user) 
    else:
        return redirect(url_for('login'))

@app.route('/captured_packets')
def captured_packets():
    if 'user_id' in session:
        user_id = session['user_id']
        
       
        # Render template with captured packets
        return render_template('captured_packets.html', packets=packets)
    else:
        return redirect(url_for('login')) 

def calculate_network_state():
    with open('captured_packets.csv', 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        packets = list(reader)

    total_packets = len(packets)
    unique_source_ips = len(set(packet['source_ip'] for packet in packets))
    unique_destination_ips = len(set(packet['destination_ip'] for packet in packets))

    total_nodes = unique_source_ips + unique_destination_ips
    
    return total_packets, unique_source_ips, unique_destination_ips, total_nodes

def count_unique_ips():
    unique_source_ips = set()
    unique_destination_ips = set()

    try:
        with open('captured_packets.csv', 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['source_ip']:
                    unique_source_ips.add(row['source_ip'])
                if row['destination_ip']:
                    unique_destination_ips.add(row['destination_ip'])
    except Exception as e:
        print(f"An error occurred while reading captured packets CSV file: {e}")

    total_source_ips = len(unique_source_ips)
    total_destination_ips = len(unique_destination_ips)

    return total_source_ips, total_destination_ips


@app.route('/logout')
def logout():
    # Remove user_id and captured_packets from session
    session.pop('user_id', None)
    session.pop('captured_packets', None)
    
    csv_filename = 'C:/Netcanvas/captured_packets.csv'
    if os.path.exists(csv_filename):
        with open(csv_filename, 'w', newline='') as csvfile:
            csvfile.truncate(0)
    
    flash("You have been logged out successfully.", 'success')
    return redirect(url_for('login'))

@app.route('/admin/login', methods=['GET', 'POST'])

def admin_login():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    form = AdminLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        isAdmin = 1

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE email=%s and isAdmin=%s", (email, isAdmin))
        admin = cursor.fetchone()
        cursor.close()

        print(f"Email and IsAdmin : {admin}")

        if admin is not None:
            hashed_password = admin[3]
            if hashed_password is not None and bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                session['admin_id'] = admin[0]
                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))

        flash("Admin login failed. Please check your email and password.", 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html', form=form)


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session:
        admin_id = session['admin_id']
        # For admin
        cursor_admin = mysql.connection.cursor()
        cursor_admin.execute("SELECT * FROM admin WHERE id=%s",(admin_id,))
        admin = cursor_admin.fetchone()
        cursor_admin.close()
        # For User List
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        cursor.close()
        
      
        print(f"Admin Id and Data {admin}")
       
        return render_template('admin_dashboard.html', users=users, admin = admin)
    else:
        flash("Please log in as an admin.",'warning')
        return redirect(url_for('admin_login'))
    
@app.route('/admin/add_user', methods=['GET', 'POST'])
def admin_add_user():
    if 'admin_id' in session:

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admin WHERE id=%s", (session['admin_id'],))
        admin = cursor.fetchone()
        form = RegisterForm()

        if form.validate_on_submit():
            name = form.name.data
            email = form.email.data
            password = form.password.data

            password_check_validation = password_checks(password)

            if password_check_validation == "Password is Valid":
                # Check the email already exists in the database
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash("This email is already taken. Please use a different email.", 'danger')
                else:
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
                    mysql.connection.commit()
                    flash("User added successfully!", 'success')
                    return redirect(url_for('admin_dashboard'))
            else:
                flash(password_check_validation , 'danger')
                return render_template('admin_add_user.html',form=form)

        cursor.close()
        return render_template('admin_add_user.html', form=form,admin = admin)
    flash("Please! login as Admin First!","danger")
    return redirect(url_for('admin_login'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    print("Attempting to delete user:", user_id)  # Check if the route is being accessed

    if 'admin_id' not in session:
        flash("Please log in as an admin.")
        return redirect(url_for('admin_login'))

    print("Admin ID in session:", session['admin_id'])  # Check the admin ID in the session

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM admin WHERE id=%s", (session['admin_id'],))
    admin = cursor.fetchone()

    print("Admin from database:", admin)  # Check if the admin is retrieved properly

    

    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    mysql.connection.commit()
    cursor.close()

    flash("User deleted successfully!",'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
def admin_update_user(user_id):
    print("Attempting to Update user:", user_id) 
    if 'admin_id' not in session:
        flash("Please log in as an admin.")
        return redirect(url_for('admin_login'))
    print("Admin ID in session:", session['admin_id']) 
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    form = RegisterForm(obj=user)

    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        password_check_validation = password_checks(password)

        if password_check_validation == "Password is Valid":
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE users SET name=%s, email=%s, password=%s WHERE id=%s",
                           (name, email, hashed_password, user_id))
            mysql.connection.commit()
            flash("User updated successfully!", 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash(password_check_validation, 'danger')

    cursor.close()
    return render_template('admin_update_user.html', form=form, user_id=user_id)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash("You have been logout successfully!", "success")
    return redirect(url_for('admin_login'))
   
if __name__ == '__main__':

    app.run(debug=True)