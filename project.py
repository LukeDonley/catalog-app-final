import random
import string
import httplib2
import json
import requests
from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

app = Flask(__name__)
#CsrfProtect(app)
app.secret_key = 'super_secret_key'

CLIENT_ID = (json.loads(open(r'/var/www/documents/client_secrets.json', 'r').read())
             ['web']['client_id'])
APPLICATION_NAME = "Catalog App"

engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalog')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Login function
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Connect to a Google Account
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(r'/var/www/documents/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Connect to a Facebook account
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open(r'/var/www/documents/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open(r'/var/www/documents/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type='
           'fb_exchange_token&client_id=%s&client_secret=%s&'
           'fb_exchange_token=%s' % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session
    # in order to properly logout, let's strip out
    # the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = ('https://graph.facebook.com/v2.4/me/picture?%s'
           '&redirect=0&height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


# Disconnect from Facebook account
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s' %
           (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect from Google account
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


# User Helper Functions.
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Show Catalog (Main page)
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.id))
    return render_template('catalog.html', categories=categories,
                               items=items)


# Show a category
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showCategory(category_id):
    currentCategory = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('category.html', categories=categories,
                           category=currentCategory, items=items)


# Show an item description
@app.route('/categories/<int:category_id>/items/<int:item_id>/')
def showItem(category_id, item_id):
    currentCategory = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    categories = session.query(Category).order_by(asc(Category.name))
    return render_template('showitem.html', item=item,
                           categories=categories, category=currentCategory)


# Create a new category
@app.route('/newCategory', methods=['GET', 'POST'])
def newCategory():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        redirect('/login')
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')


# Create a new item
@app.route('/newItem/', methods=['GET', 'POST'])
def newItem():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        return redirect('/login')
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category.id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash("New %s Item Successfully Created" % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newitem.html', categories=categories)


# Edit a category
@app.route('/editCategory/', methods=['GET', 'POST'])
def editCategory():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        return redirect('/login')
    # Select and pass to template only categories created by the current user
    categories = session.query(Category).filter_by(
        user_id=login_session['user_id']).order_by(asc(Category.name))
    if request.method == 'POST':
        editedCategory = session.query(Category).filter_by(
            name=request.form['category']).one()
        # If a new name was entered, change the name of the category
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showCatalog'))
        # Else if no name was entered, do nothing and redirect to main page
        else:
            flash('No Changes Made To Category')
            return redirect(url_for('showCatalog'))
    else:
        return render_template('editcategory.html', categories=categories)


# Edit an item
@app.route('/editItem/', methods=['GET', 'POST'])
def editItem():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        return redirect('/login')
    # Select and pass to template only items created by the current
    items = session.query(Item).filter_by(
        user_id=login_session['user_id']).order_by(asc(Item.name))
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        editedItem = session.query(Item).filter_by(
            name=request.form['old_name']).one()
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            newCategory = session.query(Category).filter_by(
                name=request.form['category']).one()
            editedItem.category_id = newCategory.id
        session.add(editedItem)
        session.commit()
        flash("Item edited!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('edititem.html',
                               items=items, categories=categories)


# Delete a category
@app.route('/deleteCategory/', methods=['GET', 'POST'])
def deleteCategory():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        return redirect('/login')
    # Select and pass to template only categories created by the current user
    categories = session.query(Category).filter_by(
            user_id=login_session['user_id']).order_by(asc(Category.name))
    if request.method == 'POST':
        categoryToDelete = session.query(Category).filter_by(
            name=request.form['old_name']).one()
        itemsToDelete = session.query(Item).filter_by(
            category_id=categoryToDelete.id).delete()
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletecategory.html', categories=categories)


# Delete an item
@app.route('/deleteItem/', methods=['GET', 'POST'])
def deleteItem():
    # If not logged in redirect to login page, flash message
    if 'username' not in login_session:
        flash('You must be logged in to do that!')
        return redirect('/login')
    # Select and pass to template only items created by the current user
    items = session.query(Item).filter_by(
        user_id=login_session['user_id']).order_by(asc(Item.name))
    if request.method == 'POST':
        itemToDelete = session.query(Item).filter_by(
            name=request.form['old_name']).one()
        session.delete(itemToDelete)
        session.commit()
        flash("Item Deleted!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteitem.html', items=items)


# JSON APIs to view Category Information
@app.route('/categories/<int:category_id>/JSON')
def categoryJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/categories/<int:category_id>/items/<int:item_id>/JSON/')
def itemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])


@app.route('/users/JSON')
def usersJSON():
    users = session.query(User).all()
    return jsonify(users=[i.serialize for i in users])


if __name__ == '__main__':
   # CsrfProtect(app)
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
