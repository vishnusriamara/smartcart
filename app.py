from flask import Flask,render_template,request,redirect,session,flash,jsonify,make_response
from flask_mail import Mail, Message 
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
import mysql.connector
import bcrypt
import random
import config
import os
from werkzeug.utils import secure_filename
import razorpay
import traceback
from utils.pdf_generator import generate_pdf
from datetime import datetime, timedelta

app=Flask(__name__)
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID,config.RAZORPAY_KEY_SECRET)
)

app.secret_key=config.secret_key

app.config['MAIL_SERVER']=config.MAIL_SERVER
app.config['MAIL_PORT']=config.MAIL_PORT
app.config['MAIL_USE_TLS']=config.MAIL_USE_TLS
app.config['MAIL_USERNAME']=config.MAIL_USERNAME
app.config['MAIL_PASSWORD']=config.MAIL_PASSWORD

mail=Mail(app)
s=URLSafeTimedSerializer(app.secret_key)
UPLOAD_FOLDER='static/uploads/product_images'
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER

ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_profiles'
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# cart={}
# session[cart]


def get_db_connection():
    conn=mysql.connector.connect(
        host=config.db_host,
        user=config.db_user,
        password=config.db_password,
        database=config.db_name
    )
    return conn

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/admin-signup')
def admin_signup():
    flash("Only Super Admin can create admins!", "danger")
    return redirect('/admin-login')

@app.route('/add-admin', methods=['GET', 'POST'])
def add_admin():

    # 🔒 Restrict access (only super admin)
    if not session.get('admin_id') or session.get('admin_role') != 'super_admin':
        flash("Access denied!", "danger")
        return redirect('/admin-dashboard')

    if request.method == 'GET':
        return render_template("admin/add_admin.html")
    
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ 1. Check if admin already exists
    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    existing_admin = cursor.fetchone()

    if existing_admin:
        flash("Admin already exists with this email!", "danger")
        cursor.close()
        conn.close()
        return redirect('/add-admin')

    # ✅ 2. Hash password properly (IMPORTANT FIX)
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')   # 👈 VERY IMPORTANT

    # ✅ 3. Insert new admin
    cursor.execute(
        "INSERT INTO admin (name, email, password, role) VALUES (%s, %s, %s, %s)",
        (name, email, hashed_password, 'admin')
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("New admin created successfully!", "success")
    return redirect('/admin-dashboard')

@app.route('/verify-otp',methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")
    
@app.route('/verify-otp',methods=['POST'])
def verify_otp_post():
    user_otp=request.form['otp']
    password=request.form['password']

    if str(session.get('otp'))!=str(user_otp):
        flash("invalid OTP. Try again!","danger")
        return redirect("/verify-otp")
    hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("insert into admin(name,email,password) values(%s,%s,%s)",(session['signup_name'],session['signup_email'],hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    session.pop('otp',None)
    session.pop('signup_name',None)
    session.pop('signup_email',None)
    flash("Admin registered successfully!","success")
    return redirect('/admin-login')

#route 4: ADMIN LOGIN PAGE

@app.route('/admin-login',methods=['GET','POST'])
def admin_login():
    if request.method=='GET':
        return render_template("admin/admin_login.html")
    email=request.form['email']
    password=request.form['password']
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute("select * from admin where email=%s",(email,))
    admin=cursor.fetchone()
    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.","danger")
        return redirect('/admin-login')
    
    stored_hashed_password=admin['password'].encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'),stored_hashed_password):
        flash("incorrect password! Try again.","danger")
        return redirect('/admin-login')
    session['admin_id']=admin['admin_id']
    session['admin_name']=admin['name']
    session['admin_email']=admin['email']
    session['admin_role']=admin['role']

    flash("Login Successful!","success")
    return redirect('/admin-dashboard')

#admin forgot password

@app.route('/admin-forgot-password')
def admin_forget_password():
    return render_template("admin/admin_forgot_password.html")

@app.route('/send-reset-link-admin',methods=["POST"])
def send_reset_link_admin():
    email=request.form['email']
    conn=get_db_connection()
    cursor=conn.cursor()
    query="select * from admin where email=%s"
    cursor.execute(query,(email,))
    admin=cursor.fetchone()
    if admin:
        token=s.dumps(email,salt="Password-reset-salt")
        link=f"http://localhost:5000/admin-reset-password/{token}"

        msg=Message("Password reset request",
                    sender="vishnusriamara@gmail.com",
                    recipients=[email])
        msg.body=f"click the link to reset your password:{link}"
        mail.send(msg)
        flash("Reset link sent to your email", "success")
        return redirect('/admin-login')
    conn.commit()
    cursor.close()
    conn.close()
    flash("Email not registered. Please register first.", "danger")
    return redirect("/")

@app.route('/admin-reset-password/<token>',methods=['GET','POST'])
def admin_reset_password(token):
    try:
        email=s.loads(token,salt='Password-reset-salt',max_age=500)
    except SignatureExpired:
        return "Link expired! Try again."
    
    if request.method=="POST":
        new_password=request.form['password']
        hashed_password=bcrypt.hashpw(new_password.encode('utf-8'),bcrypt.gensalt())
        conn=get_db_connection()
        cursor=conn.cursor()
        query="update admin set password=%s where email=%s"
        cursor=conn.cursor()
        cursor.execute(query,(hashed_password,email))
        conn.commit()
        cursor.close()
        flash("Password reset successful. Please login.", "success")
        return redirect("/admin-login")
    return render_template("admin/admin_reset_password.html")

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Counts
    cursor.execute("SELECT COUNT(*) AS total FROM products")
    total_products = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS total FROM orders")
    total_orders = cursor.fetchone()['total']

    cursor.execute("SELECT SUM(amount) AS revenue FROM orders")
    result = cursor.fetchone()
    revenue = result['revenue'] if result['revenue'] else 0

    # Last 7 days orders
    cursor.execute("""
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM orders
        WHERE created_at >= CURDATE() - INTERVAL 7 DAY
        GROUP BY DATE(created_at)
        ORDER BY day
    """)
    orders_data = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/dashboard.html",
        total_products=total_products,
        total_orders=total_orders,
        revenue=revenue,
        orders_data=orders_data
    )

# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
@app.route('/admin/add-item',methods=['GET'])
def add_item_page():
    if 'admin_id' not in session:
        flash("please login first!","danger")
        return redirect('/admin-login')
    return render_template("admin/add_item.html")

# ROUTE 8: ADD PRODUCT INTO DATABASE
@app.route('/admin/add-item', methods=['GET', 'POST'])
def add_item():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        price = request.form['price']

        image_files = request.files.getlist('images')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert product first
        cursor.execute("""
            INSERT INTO products(name, description, category, price)
            VALUES (%s, %s, %s, %s)
        """, (name, description, category, price))

        product_id = cursor.lastrowid

        # Save multiple images
        for image_file in image_files:
            if image_file.filename != "":
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)

                cursor.execute("""
                    INSERT INTO product_images(product_id, image)
                    VALUES (%s, %s)
                """, (product_id, filename))

        conn.commit()
        conn.close()

        flash("Product added with multiple images!", "success")
        return redirect('/admin/add-item')

    return render_template('add_item.html')


# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):
    if 'admin_id' not in session:
        flash("Please login first!","danger")
        return redirect('/admin-login')
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute("select * from products where product_id=%s",(item_id,))
    product=cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!","danger")
        return redirect('/admin/item-list')
    return render_template("admin/view_item.html",product=product)

# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')

# UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )

# DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch product to get image name
    cursor.execute("SELECT image FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')

@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')

@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_id',None)
    session.pop('admin_name',None)
    session.pop('admin_email',None)
    flash("admin logged-out successfully","success")
    return redirect('/admin-login')

@app.route('/user-register',methods=['GET','POST'])
def user_register():
    if request.method=="GET":
        return render_template("user/user_register.html")
    name=request.form['name']
    email=request.form['email']
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute("select user_id from users where email=%s",(email,))
    existing_user=cursor.fetchone()
    cursor.close()
    conn.close()
    if existing_user:
        flash("This email is already registered.Please login instead.","danger")
        return redirect('/user-register')
    session['signup_name']=name
    session['signup_email']=email

    otp=random.randint(100000,999999)
    session['otp']=otp

    message=Message(
        subject="SmartCart User OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body=f"your OTP for smartcart User Registration:{otp}"
    mail.send(message)
    flash("OTP sent to your email!","success")
    return redirect('/verify-user-otp')

@app.route('/verify-user-otp',methods=['GET'])
def verify_user_otp_get():
    return render_template("user/verify_otp.html")
    
@app.route('/verify-user-otp',methods=['POST'])
def verify_user_otp_post():
    user_otp=request.form['otp']
    password=request.form['password']

    if str(session.get('otp'))!=str(user_otp):
        flash("invalid OTP. Try again!","danger")
        return redirect("/verify-user-otp")
    hashed_password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("insert into users(name,email,password) values(%s,%s,%s)",(session['signup_name'],session['signup_email'],hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    session.pop('otp',None)
    session.pop('signup_name',None)
    session.pop('signup_email',None)
    flash("user registered successfully!","success")
    return redirect('/user-login')

@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')
#user forgot password

@app.route('/user-forgot-password')
def user_forget_password():
    return render_template("user/user_forgot_password.html")

@app.route('/send-reset-link-user',methods=["POST"])
def send_reset_link_user():
    email=request.form['email']
    conn=get_db_connection()
    cursor=conn.cursor()
    query="select * from users where email=%s"
    cursor.execute(query,(email,))
    admin=cursor.fetchone()
    if admin:
        token=s.dumps(email,salt="Password-reset-salt")
        link=f"http://localhost:5000/user-reset-password/{token}"

        msg=Message("Password reset request",
                    sender="vishnusriamara@gmail.com",
                    recipients=[email])
        msg.body=f"click the link to reset your password:{link}"
        mail.send(msg)
        flash("Reset link sent to your email", "success")
        return redirect('/user-login')
    conn.commit()
    cursor.close()
    conn.close()
    flash("Email not registered. Please register first.", "danger")
    return redirect("/")

@app.route('/user-reset-password/<token>',methods=['GET','POST'])
def user_reset_password(token):
    try:
        email=s.loads(token,salt='Password-reset-salt',max_age=500)
    except SignatureExpired:
        return "Link expired! Try again."
    
    if request.method=="POST":
        new_password=request.form['password']
        hashed_password=bcrypt.hashpw(new_password.encode('utf-8'),bcrypt.gensalt())
        conn=get_db_connection()
        cursor=conn.cursor()
        query="update users set password=%s where email=%s"
        cursor=conn.cursor()
        cursor.execute(query,(hashed_password,email))
        conn.commit()
        cursor.close()
        flash("Password reset successful. Please login.", "success")
        return redirect("/user-login")
    return render_template("user/user_reset_password.html")


@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Fetch all active products
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    print("Products:", products) 

    return render_template("user/user_home.html", user_name=session['user_name'],products=products)

@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')

@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )

# ROUTE: USER PRODUCT DETAILS PAGE
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)

# ADD ITEM TO CART
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
   # return redirect('/user/cart')    instead of this line use below line
    return redirect(request.referrer)

# VIEW CART PAGE
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

# INCREASE QUANTITY
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')

# DECREASE QUANTITY
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')

# REMOVE ITEM
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart
    flash("Item removed!", "success")
    return redirect('/user/cart')

# ROUTE: CREATE RAZORPAY ORDER
@app.route('/user/pay')
def user_pay():
    if 'user_id' not in session:
        flash("Please login!","danger")
        return redirect('/user-login')
    
    cart=session.get('cart',{})
    if not cart:
        flash("Your cart is empty!","danger")
        return redirect('/user-login')
    total_amount = sum(item['price']*item['quantity'] for item in cart.values())
    razorpay_amount=int(total_amount*100)
    razorpay_order=razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency":"INR",
        "payment_capture":"1"
    })
    session['razorpay_order_id']=razorpay_order['id']
    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )

# TEMP SUCCESS PAGE (Verification in Day 13)
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!","danger")
        return redirect('/user/cart')
    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )

# Route: Verify Payment and Store Order
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.","danger")
        return redirect('/user-login')
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')
    address = request.form.get('address','')

    if not(razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).","danger")
        return redirect('/user/cart')
    
    payload={
        'razorpay_order_id':razorpay_order_id,
        'razorpay_payment_id':razorpay_payment_id,
        'razorpay_signature':razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        app.logger.error("Razorpay signature verification failed: %s",str(e))
        flash("Payment verification failed. Please contact support.","danger")
        return redirect('/user/cart')
    
    user_id = session['user_id']
    cart = session.get('cart',{})

    if not cart:
        flash("cart is empty. Cannot create order.","danger")
        return redirect('/user/products')
    
    total_amount = sum(item['price']*item['quantity'] for item in cart.values())
    conn =get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""insert into orders(user_id,razorpay_order_id,razorpay_payment_id,amount,payment_status,address) values(%s,%s,%s,%s,%s,%s)""",(user_id,razorpay_order_id,razorpay_payment_id,total_amount,'paid',address))
        order_db_id = cursor.lastrowid

        for pid_str,item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""insert into order_items(order_id,product_id,product_name,quantity,price) values(%s,%s,%s,%s,%s)""",
                           (order_db_id,product_id,item['name'],item['quantity'],item['price']))
        conn.commit()
        session.pop('cart',None)
        session.pop('razorpay_order_id',None)
        flash("Payment successful and order placed!","success")
        return redirect(f"/user/order-success/{order_db_id}")
    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s",str(e),traceback.format_exc())
        flash("There was an error saving your order.Contact support.","danger")
        return redirect('/user/cart')
    finally:
        cursor.close()
        conn.close()

#✅ Route: Order Success Page

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!","danger")
        return redirect('/user-login')
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute("select * from orders where order_id=%s and user_id=%s",(order_db_id,session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_db_id,))
    items = cursor.fetchall()
    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')
    return render_template("user/order_success.html", order=order, items=items)

#route to let users view past orders:
@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)

# GENERATE INVOICE PDF

@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):
    if 'user_id' not in session:
        flash("Please login!","danger")
        return redirect('/user-login')
    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)
    cursor.execute("select * from orders where order_id=%s and user_id=%s",(order_id,session['user_id']))
    order=cursor.fetchone()
    cursor.execute(
    "SELECT * FROM order_items WHERE order_id = %s",(int(order_id),))
    items=cursor.fetchall()
    cursor.close()
    conn.close()
    if not order:
        flash("Order not found.","danger")
        return redirect('/user/my-orders')
    html=render_template("user/invoice.html",order=order,items=items)
    pdf=generate_pdf(html)
    if not pdf:
        flash("Error generating PDF","danger")
        return redirect('/user/my-orders')
    response=make_response(pdf.getvalue())
    response.headers['Content-Type']='application/pdf'
    response.headers['Content-Disposition']=f"attachment;filename=invoice_{order_id}.pdf"
    return response
# ADMIN: VIEW ALL ORDERS
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, 
               o.payment_status, o.order_status, o.created_at,
               u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)

# ADMIN: VIEW ORDER DETAILS
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders WHERE order_id=%s", (order_id,))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)

# ADMIN: UPDATE ORDER STATUS
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET order_status=%s WHERE order_id=%s",
                    (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")

if __name__=="__main__":
    app.run(debug=True)