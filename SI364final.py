#Import
import os
import requests
import json
import datetime
import requests
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask import jsonify
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename

from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

#Login import
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash


#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.debug = True
app.use_reloader = True
#Config
app.config['SECRET_KEY'] = 'alkj'
app.config["SQLALCHEMY_DATABASE_URI"] =  os.environ.get('DATABASE_URL') or "postgres://keyariaw@localhost/keyariawFinal"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['HEROKU_ON'] = os.environ.get('HEROKU')

#Migrate
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

#Login Config
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

def make_shell_context():
    return dict(app=app, db=db, User=User, Kanji=Kanji, KanjiCollection=KanjiCollection, Journal=Journal,Search=Search)
# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))
#Assoiation tables
search_kan = db.Table('search_kanji', db.Column('kanji_id', db.Integer, db.ForeignKey('Kanji.id')), db.Column('search_terms_id', db.Integer, db.ForeignKey('Search.id')))

user_collection = db.Table('user_collection', db.Column('kanji_id', db.Integer, db.ForeignKey('Kanji.id')), db.Column('Kanji_Collection_id', db.Integer, db.ForeignKey('Collections.id')))

##Models##
class User(db.Model, UserMixin):
	__tablename__ = "users" # This was built to go with Google specific auth
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(100), unique=True, nullable=False)
	name = db.Column(db.String(100), nullable=True)
	password_hash = db.Column(db.String(128))
	profilimg = db.Column(db.String(100))
	created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
	collection = db.relationship('KanjiCollection',backref='User')

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

class Kanji(db.Model):
	__tablename__ = "Kanji"
	id = db.Column(db.Integer, primary_key=True)
	character = db.Column(db.String(10))
	meaning = db.Column(db.String(256))
	strokes = db.Column(db.Integer)
	onyomi = db.Column(db.String(30))
	kunyomi = db.Column(db.String(30))
	example = db.Column(db.String(256)) 

	def __repr__(self):
		return "{}, URL: {}".format(self.character,self.meaning)

class KanjiCollection(db.Model):
	__tablename__ = "Collections"
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(255))
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
	kanji = db.relationship('Kanji',secondary=user_collection,backref=db.backref('Collections',lazy='dynamic'),lazy='dynamic')

class Journal(db.Model):
	__tablename__ = "Journals"
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	title =  db.Column(db.String(255))
	text = db.Column(db.String(500))
	created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())


class Search(db.Model):
	__tablename__ = "Search"
	id = db.Column(db.Integer, primary_key=True)
	term = db.Column(db.String(32),unique=True) 
	kanji = db.relationship('Kanji',secondary=search_kan,backref=db.backref('Search',lazy='dynamic'),lazy='dynamic')

	def __repr__(self):
		return "{} : {}".format(self.id, self.term)

class UploadForm(FlaskForm):
    file = FileField()
##Login help##
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

def get_google_auth(state=None, token=None):
	if token:
		return OAuth2Session(Auth.CLIENT_ID, token=token)
	if state:
		return OAuth2Session(
			Auth.CLIENT_ID,
			state=state,
			redirect_uri=Auth.REDIRECT_URI)
	oauth = OAuth2Session(
		Auth.CLIENT_ID,
		redirect_uri=Auth.REDIRECT_URI,
		scope=Auth.SCOPE)
	return oauth
##Forms##
class RegistrationForm(FlaskForm):
	email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
	username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	file = FileField()
	submit = SubmitField('Register User')

	
	def validate_email(self,field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self,field):
		if User.query.filter_by(name=field.data).first():
			raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

class KanjiSearchForm(FlaskForm):
	search = StringField("Enter a Kanji to search for the meaning", validators=[Required()])
	submit = SubmitField('Submit')    

class CollectionCreateForm(FlaskForm):
	name = StringField('Collection Name')
	kanji_picks = SelectMultipleField('Kanji to include')
	submit2 = SubmitField("Create Kanji List")

class JournalCreateForm(FlaskForm):
	name = StringField('Journal Name')
	text = StringField('Enter text')
	submit1 = SubmitField("Create Journal Entry")

	def validate_name(self,field):
		if len((field.data)) <= 1:
			raise ValidationError('name must be longer')

class UpdateButtonForm(FlaskForm):
	submit = SubmitField('Update')


class UpdateJournalForm(FlaskForm):
	updateText = StringField("Update Text", validators=[Required()])
	submit = SubmitField('Update')

class DeleteButtonForm(FlaskForm):
	submit = SubmitField('Delete')

##Helpers##
#Grab tranlation from google translate 
def grab_rec():
	url = "https://kitsu.io/api/edge/trending/manga?limit=5"

	search = json.loads(requests.get(url=url).text)

		#rint(search['data'][i]['attributes']['titles']['en_jp'])

	return search['data']

def grab_from_ka(kanji):
	url = "https://kanjialive-api.p.mashape.com/api/public/kanji/"
	#param = {":character": kanji}
	
	headers={
	"X-Mashape-Key": "A2hxIZpMOjmshMeDMlwbWhNzfSW1p1Si7m3jsnVUWIS0uME5H8"
  }
	
	search = (requests.get(url=url+kanji, headers=headers)).json()

	return search
##Grab Kanji
def get_kanji_by_id(id):
    """Should return gif object or None"""
    k = Kanji.query.filter_by(id=id).first()
    return k
#Grabs the kanji information from form and checks if it is in database and if not gets it from API
def get_or_create_kanji(kan,mean,stro,on,kun,exa):
	kanj = db.session.query(Kanji).filter_by(character=kan).first()
	if kanj:
		return kanj
	else:
		kanj = Kanji(character=kan,meaning=mean,strokes=stro,onyomi=on,kunyomi=kun,example=exa)
		db.session.add(kanj)
		db.session.commit()
		return kanj

#Checks for search term is in database if not puts it in there.
def get_or_create_search_term(term):
	
	ter = db.session.query(Search).filter_by(term=term).first()

	if ter:
		return ter
	else:

		ter = Search(term=term)

		lis = grab_from_ka(term)
		example = lis['examples'][0]['japanese'] + ' ' + lis['examples'][0]['meaning']['english']
		#for i in lis['kanji']:
			#add the mp4
		print(lis['kanji']['character'])
		i = get_or_create_kanji(lis['kanji']['character'],lis['kanji']['meaning']['english'], lis['kanji']['strokes']['count'],lis['kanji']['onyomi']['katakana'],lis['kanji']['kunyomi']['hiragana'],example)

		ter.kanji.append(i)

#Creates or checks for the journals 
def get_or_create_collection(name, current_user, text):
	
	journal = db.session.query(Journal).filter_by(title=name,user_id=current_user.id).first()

	if journal:
		return journal
	else:
		journal = Journal(title=name,user_id=current_user.id,text=text)

		db.session.add(journal)
		db.session.commit()
		return journal
#Checkes or create kanji list
def kanji_collection(name, current_user, kanji_list=[]):
	
	collection = db.session.query(KanjiCollection).filter_by(name=name, user_id=current_user.id).first()
	if collection:
		return collection
	else:
		collection = KanjiCollection(name=name,user_id=current_user.id,kanji=[])
		for i in kanji_list:

		   # ey = get_or_create_gif(i,'')
			collection.kanji.append(i)

		db.session.add(collection)
		db.session.commit()
		return collection
##View Function##
## Error handling routes
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
	return render_template('500.html'), 500

## Login routes
@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('index'))
		flash('Invalid username or password.')
	return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

#Register the user.
@app.route('/register',methods=["GET","POST"])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,name=form.username.data,password=form.password.data,profilimg=form.file.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in!')
		return redirect(url_for('login'))
	return render_template('register.html',form=form)

@app.route('/base')
def base():
	fil = url_for('static', filename=os.path.join('imgs', current_user.profilimg))
	return render_template('base.html',im=fil)
@app.route('/secret')
@login_required
def secret():
	return "Only authenticated users can do this! Try to log in or contact the site admin."

#Should render search form for translation and allow people who
#are not log in to use this as well.
@app.route('/', methods=['GET', 'POST'])
def index():
	form = KanjiSearchForm()
	search_kan = Search.query.all()
	
	#search = grab_rec()
		#get_or_create_search_term(request.args)
		#return redirect(url_for('search_results',search_term=request.args))
	return render_template('index.html',form=form,terms=search_kan)


#Will show the kanji search results
@app.route('/kanji_searched',  methods=['POST', 'GET'])
def search_results():
	form = KanjiSearchForm()
	empty_field = []

	search = request.args['search']
	
	if search == '':
		empty_field.append('Nothing searched')
	else:
		search = request.args['search']
		get_or_create_search_term(search)
		return redirect(url_for('search_terms',term=search))

	flash(empty_field)
	#term = Search.query.filter_by(term=search_term).first()
	
	return redirect(url_for('index'))
	

#Will show all the searched kanji
@app.route('/search_terms/<term>')
def search_terms(term):
	#kj = term.kanji.all()
	kan = Search.query.filter_by(term=term).first()
	kj = kan.kanji.all()
	#kan_in = [(i.character, i.meaning,Kanji.query.filter_by(id = i.id).first().strokes) for i in kj] 
	return render_template('kanji_searched.html',kan=kj)
#where to put kanji and should login be required if you want users to see 
#and update ither users
@app.route('/create_journal',methods=["GET","POST"])
@login_required
def create_journal():
	form = JournalCreateForm()
	
	form2 = CollectionCreateForm()
	kanji = Kanji.query.all()
	choice = [(k.id, k.character) for k in kanji]
	form2.kanji_picks.choices = choice

	if request.method == 'POST' and form.submit1.data and form.validate():
   
		collect = get_or_create_collection(form.name.data, current_user, form.text.data)
		return redirect(url_for('journal_kanji', collect=collect))

	if request.method == 'POST' and form2.submit2.data:
		lis_got = form2.kanji_picks.data

		col_picks = [get_kanji_by_id(int(id)) for id in lis_got]
		get_it = kanji_collection(form2.name.data,current_user, col_picks)
		return redirect(url_for('journal_kanji', get_it=get_it))
	errors = [v for v in form.errors.values()]
	if len(errors) > 0:
		flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))

	return render_template('create_journal.html', form=form, form2=form2)


#Here you can see the journal entries and kanji list 
@app.route('/journal',methods=["GET","POST"])
@login_required
def journal_kanji():
	form = DeleteButtonForm()
	collection = db.session.query(Journal).filter_by(user_id=current_user.id)
	kj_col = db.session.query(KanjiCollection).filter_by(user_id=current_user.id)

	return render_template('collections.html', collections=collection, kj_col=kj_col,form=form)

#Can see journal here
@app.route('/journal/<id_num>')
def single_journal(id_num):
	#id_nu = int(id_num)
	form = UpdateButtonForm()

	collection = Journal.query.filter_by(id=id_num).first()

	return render_template('journal.html',collection=collection,form=form)
@app.route('/kanjilist/<id_num>')
def kanji_list(id_num):
	kj_col = KanjiCollection.query.filter_by(id=id_num).first()
	all_kanji = kj_col.kanji.all()
	return render_template('kanji_list.html', kanji_col=kj_col,kanji=all_kanji)

#Can update the journal or kanji list here. 
@app.route('/update/<item>',methods=["GET","POST"])
def update(item):

	form = UpdateJournalForm()
	if form.validate_on_submit():
		new_up = form.updateText.data
		p = Journal.query.filter_by(text=item).first()
		p.text = new_up
		db.session.commit()
		flash("Updated Text of " + item)
		return redirect(url_for('journal_kanji'))

	return render_template('update_item.html',item = item, form = form)

#Delete a journal or kanji entry here 
@app.route('/delete/<lst>',methods=["GET","POST"])
def delete(lst):	
	lit = Journal.query.filter_by(title=lst).first()

	db.session.delete(lit)
	db.session.commit()

	return redirect(url_for('journal_kanji'))



@app.route('/ajax')
def great_search():
	
	x = jsonify({'manga':[{'name': i['attributes']['titles']['en_jp']} for i in grab_rec() ]})
	print(x)
	#rint(search['data'][i]['attributes']['titles']['en_jp'])
   # x = jsonify({"livingston" : [{'name' : restaurant['restaurant']['name']} for restaurant in grab_from_ka("American", "Livingston, NJ")]})
	return x

@app.route('/register', methods=['GET', 'POST'])
def upload():
	form3 = UploadForm()
	if form.validate_on_submit():
		filename = secure_filename(form.file.data.filename)
		form.file.data.save('static/img/' + filename) # Get file data due to the way the form specifies it -- FileField is special
        # Then can save it wherever you direct it to be saved
        # Can also save File Blobs to database --
		
		return redirect(url_for('upload'))

	return render_template('register.html', form3=form)



if __name__ == '__main__':
	db.create_all()
	manager.run()








