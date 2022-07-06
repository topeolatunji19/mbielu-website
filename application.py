import threading
from flask import Flask, render_template, redirect, url_for, flash, abort, request, jsonify
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import AddItem, RegisterForm, LoginForm, CartForm, UpdateProfileForm, PaymentMethod, ForgotPasswordForm, \
    GetOtpForm, ResetPasswordForm, RegisterEmailForm
from sqlalchemy import Table, Column, Integer, String, Text, create_engine, ForeignKey, Float, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from functools import wraps
from flask_gravatar import Gravatar
import os
import time
from random import randint
import boto3
from botocore.exceptions import ClientError

application = Flask(__name__)
application.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap(application)

test_db = os.environ.get("TEST_DB")
DATABASE_URI = os.environ.get("DATABASE_URI")
application.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
# print(application.config['SQLALCHEMY_DATABASE_URI'])
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(application)

Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(application)

gravatar = Gravatar(application,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    with Session(engine) as session:
        return session.query(User).get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


class User(Base, UserMixin):

    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False, unique=True)
    firstname = Column(String(250), nullable=False)
    lastname = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    phone = Column(String(11), nullable=False, unique=True)
    state = Column(String(50))
    address = Column(Text)

    # Relate user to the catalog
    items = relationship("Catalog", back_populates='seller')
    cart = relationship("CartItems", back_populates='buyer')

    # Relate user to actual orders
    order = relationship("Orders", back_populates='buyer')


class Catalog(Base):

    __tablename__ = "catalog"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    img_url = Column(String(500), nullable=False)
    quantity = Column(Integer, nullable=False)
    description = Column(Text, nullable=False)
    on_sale = Column(String(12))
    price = Column(Float, nullable=False)
    old_price = Column(Float)
    category = Column(String(250))
    new_arrival = Column(String(12))
    activated = Column(String(12))

    # relate item to seller
    seller = relationship("User", back_populates='items')
    # relate item to buyer
    cart = relationship("CartItems", back_populates='cart_item')

    seller_id = Column(Integer, ForeignKey("user.id"))


class CartItems(Base):
    __tablename__ = "cart"
    id = Column(Integer, primary_key=True)
    quantity = Column(Integer, nullable=False)

    # relate cart to buyer
    buyer_id = Column(Integer, ForeignKey("user.id"))
    buyer = relationship("User", back_populates='cart')

    # relate cart to items
    item_id = Column(Integer, ForeignKey("catalog.id"))
    cart_item = relationship("Catalog", back_populates="cart")


class Orders(Base):
    __tablename__ = "order"
    id = Column(Integer, primary_key=True)

    user_order = Column(Text, nullable=False)
    payment_method = Column(String(250), nullable=False)
    order_status = Column(String(20), nullable=False)
    state = Column(String(20), nullable=False)
    address = Column(Text, nullable=False)
    total_cost = Column(Float, nullable=False)
    order_id = Column(String(20))

    buyer_id = Column(Integer, ForeignKey("user.id"))
    buyer = relationship("User", back_populates='order')


class Products(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True)
    product_id = Column(String(1000), nullable=False)
    price_id = Column(String(1000))


class ForgotUsers(Base):
    __tablename__ = "forgot_users"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False, unique=True)
    otp = Column(String(10))


engine = create_engine(DATABASE_URI)

# Base.metadata.create_all(engine)


def number_of_cart_items(user_id):
    with Session(engine) as session:
        cart_rows = session.query(CartItems).filter_by(buyer_id=user_id).count()
        return cart_rows


@application.route("/")
def home():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(activated="yes_option").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1631173716529-fd1696a807b0?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxzZWFyY2h8M3x8c3RhdGlvbmVyeXxlbnwwfHwwfHw%3D&auto=format&fit=crop&w=800&q=60"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Fembs Investment Limited", category_img=category_img)


@application.route("/stationery")
def shop_stationery():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Stationery").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1456735190827-d1262f71b8a3?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxzZWFyY2h8Mnx8c3RhdGlvbmVyeXxlbnwwfHwwfHw%3D&w=1000&q=80/2046x500"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Stationery", category_img=category_img)


@application.route("/computers")
def shop_computers():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Computers").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://www.cnet.com/a/img/resize/749c306c97f14076499981fc018dace33d0e367d/hub/2018/02/13/" \
                       "517fda12-de2a-4c3f-bee5-05daaf870537/01laptops-with-longest-battery-life-2018-feb.jpg?" \
                       "auto=webp&width=1200"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items, header_text="Computers", category_img=category_img)


@application.route("/safes")
def shop_safes():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Safes").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://www.rottner-security.co.za/media/rottner-uk/Teasers/teaser_fireproof_safes.jpg"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items, header_text="Safes", category_img=category_img)


@application.route("/printers")
def shop_printers():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Printers").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://i1.adis.ws/i/canon/1_a3_professional_photo_printers_137125259380583?$og-image$"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items, header_text="Printers", category_img=category_img)


@application.route("/shredders")
def shop_shredders():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Shredders").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://cdn.mos.cms.futurecdn.net/NX6KqQHBdRVnckkVzTWkzJ.jpeg"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Paper Shredders", category_img=category_img)


@application.route("/printer-supplies")
def shop_printer_supplies():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Printer Supplies").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1503694978374-8a2fa686963a?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1769&q=80"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Printer Supplies", category_img=category_img)


@application.route("/document-folders")
def shop_document_folders():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Document Folders").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1584628804572-f84284d9f388?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxzZWFyY2h8N3x8Zm9sZGVyfGVufDB8fDB8fA%3D%3D&auto=format&fit=crop&w=800&q=60"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Document Folders", category_img=category_img)


@application.route("/document-bags")
def shop_document_bags():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Document Bags").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1517612228538-cefdbc2c01e7?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1770&q=80"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="Document Bags", category_img=category_img)


@application.route("/envelopes")
def shop_envelopes():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(category="Envelopes").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1510070112810-d4e9a46d9e91?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1769&q=80"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items, header_text="Envelopes", category_img=category_img)


@application.route("/new-arrivals")
def shop_new_arrivals():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(new_arrival="yes_option").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://img.freepik.com/free-vector/new-arrival-design_23-2147886979.jpg?" \
                       "t=st=1657019614~exp=1657020214~hmac=0b43eb885189d41cf2412ffc945beb8ae45e8d32a0a6c6e9" \
                       "cab48733fa7f21a8&w=1380"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="New Arrivals!", category_img=category_img)


@application.route("/on-sale")
def shop_on_sale():
    with Session(engine) as session:
        items = session.query(Catalog).filter_by(on_sale="Yes").order_by(desc(Catalog.id)).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        category_img = "https://images.unsplash.com/photo-1607083206968-13611e3d76db?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1830&q=80"
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items,
                           header_text="On Sale!", category_img=category_img)


@application.route("/register-email", methods=["GET", "POST"])
def register_email():
    form = RegisterEmailForm()
    if form.validate_on_submit():
        with Session(engine) as session:
            email = form.email.data
            check_email = session.query(User).filter_by(email=email).first()
            check_forgot_password = session.query(ForgotUsers).filter_by(email=email).first()
            if check_email:
                flash("This email is already registered with us. Login Instead.")
                return redirect(url_for('login'))
            elif check_forgot_password:
                flash("This email is currently undergoing a process with us and cannot generate a new OTP")
            else:
                unid = get_unique_id(email)
                new_forgotten_user = ForgotUsers(
                    email=email,
                    otp=unid
                )
                session.add(new_forgotten_user)
                session.commit()
                SENDER = "Fembs Investment Ltd. <tunjipy@gmail.com>"
                RECIPIENT = email
                # CONFIGURATION_SET = "ConfigSet"
                AWS_REGION = "us-east-1"
                # The subject line for the email.
                SUBJECT = "OTP from Fembs Investment Ltd."

                # The email body for recipients with non-HTML email clients.
                BODY_TEXT = (f"Your one time password is {unid}.\r\n"
                             "It expires in 30 minutes."
                             )

                # The HTML body of the email.
                BODY_HTML = f"""<html>
                    <head></head>
                    <body>
                      <h3>Your one time password is {unid}.</h3>
                      <p>It expires in 30 minutes.
                      </p>
                    </body>
                    </html>
                                """

                # The character encoding for the email.
                CHARSET = "UTF-8"

                # Create a new SES resource and specify a region.
                client = boto3.client('ses', region_name=AWS_REGION)

                # Try to send the email.
                try:
                    # Provide the contents of the email.
                    response = client.send_email(
                        Destination={
                            'ToAddresses': [
                                RECIPIENT,
                            ],
                        },
                        Message={
                            'Body': {
                                'Html': {
                                    'Charset': CHARSET,
                                    'Data': BODY_HTML,
                                },
                                'Text': {
                                    'Charset': CHARSET,
                                    'Data': BODY_TEXT,
                                },
                            },
                            'Subject': {
                                'Charset': CHARSET,
                                'Data': SUBJECT,
                            },
                        },
                        Source=SENDER,
                        # If you are not using a configuration set, comment or delete the
                        # following line
                        # ConfigurationSetName=CONFIGURATION_SET,
                    )
                # Display an error if something goes wrong.
                except ClientError as e:
                    print(e.response['Error']['Message'])
                else:
                    print("Email sent! Message ID:"),
                    print(response['MessageId'])

                threading.Thread(target=create_timer, args=(email, unid, 30,)).start()
                return redirect(url_for('register', email=email))
                # REST response to application to verify at client side
    return render_template("new-user.html", form=form)


@application.route('/register', methods=["GET", "POST"])
def register():
    email = request.args.get('email')
    form = RegisterForm(email=email)
    if form.validate_on_submit():
        with Session(engine) as session:
            user_email = email
            user_firstname = form.firstname.data
            user_lastname = form.lastname.data
            user_phone = form.phone.data
            user_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            initial_password = form.password.data
            confirm_password = form.confirm_password.data
            user_otp = form.otp.data
            check_email = session.query(User).filter_by(email=user_email).first()
            check_phone = session.query(User).filter_by(phone=user_phone).first()
            forgot_user_data = session.query(ForgotUsers).filter_by(email=user_email).first()
            if not forgot_user_data:
                flash("Session expired. Start the process again to get a new OTP")
            elif check_email:
                flash("This email already exists. Log in Instead.")
                return redirect(url_for('login'))
            elif len(user_phone) != 11:
                flash("Please enter a valid phone number.")
            elif check_phone:
                flash("This phone number is already assigned to a profile.")
            # elif not check_password(new_password): #check_password verify password meet requirements
            #     flash("Password too weak")

            elif user_otp != forgot_user_data.otp:
                flash("Wrong OTP")
            elif initial_password != confirm_password:
                flash("Both passwords have to match")
            else:
                new_user = User(
                    firstname=user_firstname,
                    lastname=user_lastname,
                    email=user_email,
                    password=user_password,
                    phone=user_phone
                )
                session.add(new_user)
                session.commit()
                login_user(new_user)
                SENDER = "Fembs Investment Ltd. <tunjipy@gmail.com>"
                RECIPIENT = email
                # CONFIGURATION_SET = "ConfigSet"
                AWS_REGION = "us-east-1"
                # The subject line for the email.
                SUBJECT = "Registered Successfully"

                # The email body for recipients with non-HTML email clients.
                BODY_TEXT = (f"Dear {current_user.firstname},"
                             f"Your account has been successfully registered.\r\n"
                             )

                # The HTML body of the email.
                BODY_HTML = f"""<html>
                                    <head></head>
                                    <body>
                                      <p>Dear {current_user.firstname},</p>                                    
                                      <p>Your account has been successfully registered</p>
                                      
                                    </body>
                                    </html>
                                                """

                # The character encoding for the email.
                CHARSET = "UTF-8"

                # Create a new SES resource and specify a region.
                client = boto3.client('ses', region_name=AWS_REGION)

                # Try to send the email.
                try:
                    # Provide the contents of the email.
                    response = client.send_email(
                        Destination={
                            'ToAddresses': [
                                RECIPIENT,
                            ],
                        },
                        Message={
                            'Body': {
                                'Html': {
                                    'Charset': CHARSET,
                                    'Data': BODY_HTML,
                                },
                                'Text': {
                                    'Charset': CHARSET,
                                    'Data': BODY_TEXT,
                                },
                            },
                            'Subject': {
                                'Charset': CHARSET,
                                'Data': SUBJECT,
                            },
                        },
                        Source=SENDER,
                        # If you are not using a configuration set, comment or delete the
                        # following line
                        # ConfigurationSetName=CONFIGURATION_SET,
                    )
                # Display an error if something goes wrong.
                except ClientError as e:
                    print(e.response['Error']['Message'])
                else:
                    print("Email sent! Message ID:"),
                    print(response['MessageId'])

                return redirect(url_for('home'))
    return render_template("register.html", form=form)


@application.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        with Session(engine) as session:
            user = session.query(User).filter_by(email=user_email).first()
            if not user:
                flash("This email address is not registered")
                return redirect(url_for('login'))
            else:
                if check_password_hash(user.password, user_password):
                    login_user(user)
                    return redirect(url_for('home'))
                else:
                    flash("Incorrect password. Try again")
                    return redirect(url_for("login"))
    return render_template("login.html", form=form, current_user=current_user)


@application.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@application.route('/my-profile')
def view_profile():
    if current_user.is_authenticated:
        cart_items = number_of_cart_items(current_user.id)
    else:
        cart_items = None
    return render_template("profile-page.html", current_user=current_user, logged_in=current_user.is_authenticated,
                           no_of_cart_items=cart_items)


@application.route('/payment-options', methods=["GET", "POST"])
def payment_options():
    with Session(engine) as session:
        form = PaymentMethod()
        requested_items = session.query(CartItems).filter_by(buyer_id=current_user.id).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        if form.validate_on_submit():
            order_items = {}
            for item in requested_items:
                item_name = item.cart_item.name
                item_quantity = item.quantity
                order_items[item_name] = item_quantity
            if order_items:
                user_order = str(order_items).strip("{}")
                # order_text = f"{order_items.keys}: {order_items.values}"
                # print(user_order.strip("{}"))
            else:
                user_order = "Empty"

            total_cost = float(form.total_cost.data)
            if form.payment_method.data == "on_collection":
                payment_method = "on_collection"
                state = "F.C.T - Abuja"
                address = "Our Shop"
                final_cost = total_cost
            elif form.payment_method.data == "pay_now_and_pickup":
                payment_method = "pay_now_and_pickup"
                state = "F.C.T - Abuja"
                address = "Our Shop"
                final_cost = total_cost
            elif form.payment_method.data == "on_delivery":
                if current_user.address is None:
                    flash("You have not registered an address. Add address below")
                    return redirect(url_for('edit_profile', user_id=current_user.id))
                else:
                    payment_method = "on_delivery"
                    state = current_user.state
                    address = current_user.address
                    final_cost = total_cost + 2000
            elif form.payment_method.data == "with_card":
                if current_user.address is None:
                    flash("You have not registered an address. Add address below")
                    return redirect(url_for('edit_profile', user_id=current_user.id))
                else:
                    payment_method = "with_card"
                    state = current_user.state
                    address = current_user.address
                    final_cost = total_cost + 2000

            new_order = Orders(
                user_order=user_order,
                payment_method=payment_method,
                order_status="pending",
                state=state,
                address=address,
                total_cost=final_cost,
                buyer=current_user
            )
            session.add(new_order)
            session.flush()
            # txn_ref = f"txn_txn_id{current_user.id}{new_order.id}"
            txn_ref = get_transaction_id(f"F{current_user.id}{new_order.id}")
            order_id = txn_ref

            new_order.order_id = order_id
            session.commit()
            if form.payment_method.data == "with_card" or form.payment_method.data == "pay_now_and_pickup":
                return render_template("payment-interface.html", cost=final_cost, user=current_user, tx_ref=txn_ref)
            elif form.payment_method.data == "on_collection" or form.payment_method.data == "on_delivery":
                return redirect(url_for('confirmation', tx_ref=txn_ref, status="successful"))

        return render_template("payment-options.html", form=form, current_user=current_user, items=requested_items,
                               logged_in=current_user.is_authenticated, no_of_cart_items=cart_items)


@application.route("/my-orders")
def view_orders():
    with Session(engine) as session:
        personal_orders = session.query(Orders).filter_by(buyer_id=current_user.id).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        return render_template("view-orders.html", orders=personal_orders, current_user=current_user,
                               logged_in=current_user.is_authenticated, no_of_cart_items=cart_items)


@application.route("/all-orders")
@admin_only
def view_all_orders():
    with Session(engine) as session:
        all_orders = session.query(Orders).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        return render_template("view-all-orders.html", orders=all_orders, current_user=current_user,
                               logged_in=current_user.is_authenticated, no_of_cart_items=cart_items)


@application.route("/edit_order_status/<int:order_id>", methods=["POST"])
@admin_only
def edit_order_status(order_id):
    if request.method == "POST":
        new_status = request.form["new-status"]
        with Session(engine) as session:
            order_to_edit = session.query(Orders).get(order_id)
            order_to_edit.order_status = new_status
            session.commit()
        return redirect(request.referrer)


@application.route("/cancel_order/<int:order_id>")
def cancel_order(order_id):
    with Session(engine) as session:
        requested_order = session.query(Orders).get(order_id)
        requested_order.order_status = "cancelled"
        session.commit()
        return redirect(request.referrer)


@application.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    with Session(engine) as session:
        user = session.query(User).get(current_user.id)
        update_form = UpdateProfileForm(
            firstname=user.firstname,
            lastname=user.lastname,
            email=user.email,
            phone=user.phone,
            state=user.state,
            address=user.state
        )
        if update_form.validate_on_submit():
            user_email = update_form.email.data
            user_phone = update_form.phone.data
            check_email = session.query(User).filter_by(email=user_email).first()
            check_phone = session.query(User).filter_by(phone=user_phone).first()
            if current_user.email != user_email and check_email:
                # if check_email:
                flash("This email is already assigned to another user.")
            elif len(user_phone) != 11:
                flash("Please enter a valid phone number.")
            elif current_user.phone != user_phone and check_phone:
                # if check_phone:
                flash("This phone number is already assigned to a profile.")
            else:
                user.firstname = update_form.firstname.data
                user.lastname = update_form.lastname.data
                user.email = update_form.email.data
                user.phone = update_form.phone.data
                user.state = update_form.state.data
                user.address = update_form.address.data
                session.commit()
                return redirect(url_for("view_profile"))

    return render_template("register.html", form=update_form, logged_in=current_user.is_authenticated)


@application.route("/new-item", methods=["GET", "POST"])
@admin_only
def add_new_item():
    form = AddItem()
    if form.validate_on_submit():
        with Session(engine) as session:
            if form.on_sale.data == "Yes":
                new_item = Catalog(
                    name=form.name.data,
                    img_url=form.img_url.data,
                    quantity=form.quantity.data,
                    description=form.description.data,
                    price=form.discounted_price.data,
                    on_sale=form.on_sale.data,
                    old_price=form.price.data,
                    category=form.category.data,
                    new_arrival=form.new_arrival.data,
                    activated=form.activated.data,
                    seller=current_user
                )
            else:
                new_item = Catalog(
                    name=form.name.data,
                    img_url=form.img_url.data,
                    quantity=form.quantity.data,
                    description=form.description.data,
                    price=form.price.data,
                    on_sale=form.on_sale.data,
                    category=form.category.data,
                    new_arrival=form.new_arrival.data,
                    activated=form.activated.data,
                    seller=current_user
                )
            session.add(new_item)
            session.commit()
            # with Session(engine) as new_session:
            #     new_product_item = new_session.query(Catalog).filter_by(name=new_item.name).first()
            #     print(new_product_item.id)
            #     created_product = stripe.Product.create(name=new_product_item.name,
            #                                             id=f"catalogproduct{new_product_item.id}",
            #                                             images=[new_product_item.img_url])
            #     add_price(item=new_product_item, product_id=created_product["id"])
            #     return redirect(url_for("add_new_item"))
            return redirect(url_for("add_new_item"))
    return render_template("add-item.html", form=form, logged_in=current_user.is_authenticated)


@application.route("/edit-item/<int:item_id>", methods=["GET", "POST"])
@admin_only
def edit_item(item_id):
    with Session(engine) as session:
        item = session.query(Catalog).get(item_id)
        if item.on_sale == "No":
            edit_form = AddItem(
                name=item.name,
                img_url=item.img_url,
                quantity=item.quantity,
                description=item.description,
                price=item.price,
                category=item.category,
                new_arrival=item.new_arrival,
                activated=item.activated,
                on_sale=item.on_sale,
                seller=item.seller
            )
        elif item.on_sale == "Yes":
            edit_form = AddItem(
                name=item.name,
                img_url=item.img_url,
                quantity=item.quantity,
                description=item.description,
                discounted_price=item.price,
                price=item.old_price,
                category=item.category,
                new_arrival=item.new_arrival,
                activated=item.activated,
                on_sale=item.on_sale,
                seller=item.seller
            )
        if edit_form.validate_on_submit():
            if item.on_sale == "No":
                item.name = edit_form.name.data
                item.img_url = edit_form.img_url.data
                item.quantity = edit_form.quantity.data
                item.description = edit_form.description.data
                item.price = edit_form.price.data
                item.category = edit_form.category.data
                item.new_arrival = edit_form.new_arrival.data
                item.activated = edit_form.activated.data
                item.on_sale = edit_form.on_sale.data
            elif item.on_sale == "Yes":
                item.name = edit_form.name.data
                item.img_url = edit_form.img_url.data
                item.quantity = edit_form.quantity.data
                item.description = edit_form.description.data
                item.price = edit_form.discounted_price.data
                item.category = edit_form.category.data
                item.new_arrival = edit_form.new_arrival.data
                item.activated = edit_form.activated.data
                item.on_sale = edit_form.on_sale.data
                item.old_price = edit_form.price.data
            session.commit()
            return redirect(url_for("show_item", item_id=item.id))

    return render_template("add-item.html", form=edit_form, logged_in=current_user.is_authenticated)


@application.route("/item/<int:item_id>", methods=["GET", "POST"])
def show_item(item_id):
    with Session(engine) as session:
        form = CartForm()
        requested_item = session.query(Catalog).get(item_id)
        item_category = requested_item.category
        similar_items = session.query(Catalog).filter_by(category=item_category).limit(5).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("Log in to add to cart")
                return redirect(url_for('login'))
            else:
                if current_user.id != 1:
                    new_item = CartItems(
                        buyer=current_user,
                        cart_item=requested_item,
                        quantity=form.quantity.data
                    )
                    session.add(new_item)
                    session.commit()
                    print(item_id)
                    return redirect(url_for('home'))
                else:
                    return redirect(url_for('edit_item', item_id=item_id))
        return render_template("item.html", item=requested_item, form=form, current_user=current_user,
                               logged_in=current_user.is_authenticated, no_of_cart_items=cart_items,
                               similar_items=similar_items)


@application.route("/view-cart")
def view_cart():
    with Session(engine) as session:
        requested_items = session.query(CartItems).filter_by(buyer_id=current_user.id).all()
        if current_user.is_authenticated:
            cart_items = number_of_cart_items(current_user.id)
        else:
            cart_items = None
        return render_template("view-cart.html", items=requested_items, current_user=current_user,
                               logged_in=current_user.is_authenticated, no_of_cart_items=cart_items)


@application.route("/edit-cart/<int:item_id>", methods=["POST"])
def edit_cart(item_id):
    if request.method == "POST":
        new_quantity = request.form["quantity"]
        with Session(engine) as session:
            item_to_edit = session.query(CartItems).get(item_id)
            item_to_edit.quantity = new_quantity
            session.commit()
        return redirect(url_for('view_cart'))


@application.route("/remove/<int:item_id>")
def remove_item(item_id):
    with Session(engine) as session:
        item_to_remove = session.query(CartItems).get(item_id)
        session.delete(item_to_remove)
        session.commit()
    return redirect(url_for('view_cart'))


@application.route("/add-to-cart/<int:item_id>")
def add_to_cart(item_id):
    with Session(engine) as session:
        requested_item = session.query(Catalog).get(item_id)
        if not current_user.is_authenticated:
            flash("Log in to add to cart")
            return redirect(url_for('login'))
        else:
            new_item = CartItems(
                buyer=current_user,
                cart_item=requested_item,
                quantity=1
            )
            session.add(new_item)
            session.commit()
            return redirect(request.referrer)


@application.route('/confirmation', methods=["GET", "POST"])
def confirmation():
    txn_id = request.args.get('tx_ref')
    if request.args.get('status') == "successful":
        with Session(engine) as session:
            cart_items = session.query(CartItems).filter_by(buyer_id=current_user.id).all()
            print(cart_items)
            for item in cart_items:
                session.delete(item)
            session.commit()
            SENDER = "Fembs Investment Ltd. <tunjipy@gmail.com>"
            RECIPIENT = current_user.email
            # CONFIGURATION_SET = "ConfigSet"
            AWS_REGION = "us-east-1"
            # The subject line for the email.
            SUBJECT = "Order Successful"

            # The email body for recipients with non-HTML email clients.
            BODY_TEXT = (f"Dear {current_user.firstname},"
                         f"Your order with ID {txn_id} was successful."
                         f"Thank you for your order.\r\n"
                         )

            # The HTML body of the email.
            BODY_HTML = f"""<html>
                                        <head></head>
                                        <body>
                                        <p>Dear {current_user.firstname},</p>
                                          <p>Your order with ID {txn_id} was successful.</p>
                                          <p>Thank you for your order.</p>
                                        </body>
                                        </html>
                                                    """

            # The character encoding for the email.
            CHARSET = "UTF-8"

            # Create a new SES resource and specify a region.
            client = boto3.client('ses', region_name=AWS_REGION)

            # Try to send the email.
            try:
                # Provide the contents of the email.
                response = client.send_email(
                    Destination={
                        'ToAddresses': [
                            RECIPIENT,
                        ],
                    },
                    Message={
                        'Body': {
                            'Html': {
                                'Charset': CHARSET,
                                'Data': BODY_HTML,
                            },
                            'Text': {
                                'Charset': CHARSET,
                                'Data': BODY_TEXT,
                            },
                        },
                        'Subject': {
                            'Charset': CHARSET,
                            'Data': SUBJECT,
                        },
                    },
                    Source=SENDER,
                    # If you are not using a configuration set, comment or delete the
                    # following line
                    # ConfigurationSetName=CONFIGURATION_SET,
                )
            # Display an error if something goes wrong.
            except ClientError as e:
                print(e.response['Error']['Message'])
            else:
                print("Email sent! Message ID:"),
                print(response['MessageId'])
        return render_template("success.html")
    else:
        return render_template("canceled.html")


def get_unique_id(email, no_digits=7):
    number = str(int(abs(hash(email))+time.time()))
    if len(number) < no_digits:
        added_digits = [str(randint(0, 9)) for i in range(no_digits-len(number))]
        added_string = ''.join(added_digits)
        number += added_string
    return number[:no_digits]


def get_transaction_id(ref_no, no_digits=10):
    txn_ref = ref_no
    if len(txn_ref) < no_digits:
        added_digits = [str(randint(0, 9)) for i in range(no_digits-len(txn_ref))]
        added_string = ''.join(added_digits)
        txn_ref += added_string
    return txn_ref[:no_digits]


def create_timer(email, unid, minutes=30):
    while True:
        time.sleep(60*minutes)
        with Session(engine) as session:
            forgot_user = session.query(ForgotUsers).filter_by(email=email).all()
            for user in forgot_user:
                session.delete(user)
            # deleting otp form database
            session.commit()
        print({email: unid}, "is removed")
        break


@application.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        with Session(engine) as session:
            user_email = form.email.data
            check_email = session.query(User).filter_by(email=user_email).first()
            forgot_user_data = session.query(ForgotUsers).filter_by(email=user_email).first()
            if not check_email:
                flash("This email does not exist in our database")
            elif forgot_user_data:
                flash("This email is currently undergoing a process with us and cannot generate a new OTP")
            else:
                return redirect(url_for('password_reset', email=user_email))
    return render_template("forgot-password.html", form=form)


@application.route('/password-reset', methods=['GET', 'POST'])
def password_reset():
    email = request.args.get('email')
    unid = get_unique_id(email)
    form = GetOtpForm(
        email=email
    )
    if form.validate_on_submit:
        with Session(engine) as session:
            new_forgotten_user = ForgotUsers(
                email=email,
                otp=unid
            )
            session.add(new_forgotten_user)
            session.commit()
            SENDER = "Fembs Investment Ltd. <fmbielu4@gmail.com>"
            RECIPIENT = email
            # CONFIGURATION_SET = "ConfigSet"
            AWS_REGION = "us-east-1"
            # The subject line for the email.
            SUBJECT = "OTP from Fembs Investment Ltd."

            # The email body for recipients with non-HTML email clients.
            BODY_TEXT = (f"Your one time password is {unid}.\r\n"
                         "It expires in 30 minutes."
                         )

            # The HTML body of the email.
            BODY_HTML = f"""<html>
            <head></head>
            <body>
              <p>Your one time password is {unid}.</p>
              <p>It expires in 30 minutes.
              </p>
            </body>
            </html>
                        """

            # The character encoding for the email.
            CHARSET = "UTF-8"

            # Create a new SES resource and specify a region.
            client = boto3.client('ses', region_name=AWS_REGION)

            # Try to send the email.
            try:
                # Provide the contents of the email.
                response = client.send_email(
                    Destination={
                        'ToAddresses': [
                            RECIPIENT,
                        ],
                    },
                    Message={
                        'Body': {
                            'Html': {
                                'Charset': CHARSET,
                                'Data': BODY_HTML,
                            },
                            'Text': {
                                'Charset': CHARSET,
                                'Data': BODY_TEXT,
                            },
                        },
                        'Subject': {
                            'Charset': CHARSET,
                            'Data': SUBJECT,
                        },
                    },
                    Source=SENDER,
                    # If you are not using a configuration set, comment or delete the
                    # following line
                    # ConfigurationSetName=CONFIGURATION_SET,
                )
            # Display an error if something goes wrong.
            except ClientError as e:
                print(e.response['Error']['Message'])
            else:
                print("Email sent! Message ID:"),
                print(response['MessageId'])

            threading.Thread(target=create_timer, args=(email, unid, 30,)).start()
            return redirect(url_for('password_reset_verify', request_type="password_reset"))
            # REST response to application to verify at client side
    return render_template("otp-page.html", form=form)


@application.route('/password-reset/verify', methods=['GET', 'POST'])
def password_reset_verify():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_otp = form.otp.data
        new_password = form.new_password.data
        confirm_password = form.confirm_password.data
        with Session(engine) as session:
            user_data = session.query(User).filter_by(email=user_email).first()
            forgot_user_data = session.query(ForgotUsers).filter_by(email=user_email).first()
            if not user_data:
                flash("User not present in database")
            elif not forgot_user_data:
                flash("Session OTP expired")
            # elif not check_password(new_password): #check_password verify password meet requirements
            #     flash("Password too weak")
            elif user_email != forgot_user_data.email:
                flash("Wrong Email")
            elif user_otp != forgot_user_data.otp:
                flash("Wrong OTP")
            elif new_password != confirm_password:
                flash("Confirmed password has to match new password")
            else:
                user_data.password = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=8)
                session.commit()

                SENDER = "Fembs Investment Ltd. <tunjipy@gmail.com>"
                RECIPIENT = user_email
                # CONFIGURATION_SET = "ConfigSet"
                AWS_REGION = "us-east-1"
                # The subject line for the email.
                SUBJECT = "Password changed successfully."

                # The email body for recipients with non-HTML email clients.
                BODY_TEXT = (f"Your password was successfully changed.\r\n"
                             f"You can now login with your new password."
                             )

                # The HTML body of the email.
                BODY_HTML = f"""<html>
                            <head></head>
                            <body>
                              <p>Your password was successfully changed.</p>
                              <p> You can now login with your new password. </p>
                            </body>
                            </html>
                                        """

                # The character encoding for the email.
                CHARSET = "UTF-8"

                # Create a new SES resource and specify a region.
                client = boto3.client('ses', region_name=AWS_REGION)

                # Try to send the email.
                try:
                    # Provide the contents of the email.
                    response = client.send_email(
                        Destination={
                            'ToAddresses': [
                                RECIPIENT,
                            ],
                        },
                        Message={
                            'Body': {
                                'Html': {
                                    'Charset': CHARSET,
                                    'Data': BODY_HTML,
                                },
                                'Text': {
                                    'Charset': CHARSET,
                                    'Data': BODY_TEXT,
                                },
                            },
                            'Subject': {
                                'Charset': CHARSET,
                                'Data': SUBJECT,
                            },
                        },
                        Source=SENDER,
                        # If you are not using a configuration set, comment or delete the
                        # following line
                        # ConfigurationSetName=CONFIGURATION_SET,
                    )
                # Display an error if something goes wrong.
                except ClientError as e:
                    print(e.response['Error']['Message'])
                else:
                    print("Email sent! Message ID:"),
                    print(response['MessageId'])
                flash("Password changed successfully. Login with new password")
                return redirect(url_for('login'))
                # updating new password
    return render_template("password-verification.html", form=form)


if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5000)
    # application.run(debug=True)
