from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FloatField, IntegerField, SelectField, RadioField, \
    HiddenField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

NIGERIAN_STATES = [
  "Abia",
  "Adamawa",
  "Akwa Ibom",
  "Anambra",
  "Bauchi",
  "Bayelsa",
  "Benue",
  "Borno",
  "Cross River",
  "Delta",
  "Ebonyi",
  "Edo",
  "Ekiti",
  "Enugu",
  "FCT - Abuja",
  "Gombe",
  "Imo",
  "Jigawa",
  "Kaduna",
  "Kano",
  "Katsina",
  "Kebbi",
  "Kogi",
  "Kwara",
  "Lagos",
  "Nasarawa",
  "Niger",
  "Ogun",
  "Ondo",
  "Osun",
  "Oyo",
  "Plateau",
  "Rivers",
  "Sokoto",
  "Taraba",
  "Yobe",
  "Zamfara"
]

##WTForm
class AddItem(FlaskForm):
    name = StringField("Name of Item", validators=[DataRequired()])
    description = StringField("Item Description", validators=[DataRequired()])
    img_url = StringField("Item Image URL", validators=[DataRequired(), URL()])
    category = SelectField("What category is the Item", choices=["Computers", "Stationery", "Printers",
                                                                 "Printer Supplies", "Shredders",
                                                                 "Document Folders", "Document Bags", "Envelopes",
                                                                 "Safes"])
    quantity = IntegerField("Number of items available", validators=[DataRequired()])
    price = FloatField("Unit Price", validators=[DataRequired()])
    on_sale = SelectField("Are you running a discount on this item?", choices=["No", "Yes"])
    discounted_price = FloatField("Discounted Price per unit")
    new_arrival = RadioField(label="Is this a New Arrival?", choices=[("yes_option", "Yes"), ("no_option", "No")],
                             )
    activated = RadioField(label="Is this item activated?", choices=[("yes_option", "Yes"), ("no_option", "No")],
                           default="yes_option")
    submit = SubmitField("Add Item")


class RegisterForm(FlaskForm):
    firstname = StringField("First Name", validators=[DataRequired()])
    lastname = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone Number", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    # otp = StringField("OTP", validators=[DataRequired()])
    submit = SubmitField("SIGN UP!")


class UpdateProfileForm(FlaskForm):
    firstname = StringField("First Name", validators=[DataRequired()])
    lastname = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone Number", validators=[DataRequired()])
    state = SelectField("Select State", choices=NIGERIAN_STATES)
    address = StringField("Enter Delivery Address")
    submit = SubmitField("Update Profile")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("LOG IN!")


class CartForm(FlaskForm):
    quantity = IntegerField("Quantity", validators=[DataRequired()])
    submit = SubmitField("Add to cart")


class PaymentMethod(FlaskForm):
    payment_method = RadioField(label="Select Payment Method", choices=[("on_delivery", "Payment on Delivery"),
                                                                        ("on_collection", "Payment on Collection from the Store"),
                                                                        ("with_card", "Pay Online with Card"),
                                                                        ("pay_now_and_pickup", "Pay now to secure order and pick up later")],
                                default="on_collection")
    # new_inf = IntegerField("Final Cost: ", validators=[DataRequired()])
    total_cost = HiddenField()
    confirm = SubmitField("Confirm")


class ForgotPasswordForm(FlaskForm):
    email = StringField("Enter your email address", validators=[DataRequired(), Email()])
    submit = SubmitField("Reset Password")


class ResetPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    otp = StringField("OTP", validators=[DataRequired()])
    new_password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Set new Password")


class GetOtpForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Get OTP")


class RegisterEmailForm(FlaskForm):
    email = StringField("Enter your email address", validators=[DataRequired(), Email()])
    submit = SubmitField("Register Email")

# class VerificationForm(FlaskForm):
#     otp = StringField("OTP", validators=[DataRequired()])
#     submit = SubmitField("Verify Account")

