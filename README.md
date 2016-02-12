Catalog App
===========

An app for creating a list of categories with items and descriptions.


To Run:
-------

Go to http://ec2-52-11-49-221.us-west-2.compute.amazonaws.com/catalog/ for access to the live site.
IP address for log in: 52.11.49.221  port: 2200


Add/Edit Categories/Items:
--------------------------

Adding and editing requires a user to be logged in. Click the login button from the upper right corner and log in using google or facebook.

All adding and editing functions are accessed using the navigation bar menu. 

Any logged in user can create a category or item. A user must be the creator of a cetegory or item in order to edit or delete it. Deleting a category will also delete all items contained within that category.

Software added and configuration changes to server:
---------------------------------------------------

Updated all software using apt-get update & apt-get upgrade
Added user "grader". Gave grader sudo access by adding grader file to sudoers.d.
Added a new ssh key for grader and changed file permissions to allow access.
Configure ufw to allow only ports 2200, 80 and 123. Enabled the firewall.
Installed apache2, libapache2-mod-wsgi, postgresql and git.
Configured postgresql: added user catalog. Granted user catalog priveleges to SELECT, INSERT, UPDATE and DELETE all tables in the catalog database as well as granting priveleges fo the sequences.
Cloned my Catalog App into /var/www/documents/ directory and configured apache2 and myapp.wsgi to run the Catalog App from appropriate directories.
Installed pip and all necessary Python packages (flask, sqlalchemy, httplib2, oauth2client, python-psycopg).
Changed the create_engine database connection to connect to postgresql using the user "catalog".
Changed urls for third party authentication. Updated client_secrets.json.

Third Party Resources used:
---------------------------

askubuntu.com, stackoverflow.com - searched here a lot for questions/solutions to problems i was having.

