echo --------------------------INSTALLING PYTHON DEPENDENCIES------------------------
sudo apt install build-essential -y
apt-get install python3-dev -y
apt-get install libpq-dev -y
apt install python3-venv -y
python3 -m venv ./venv/
source venv/bin/activate
#installing psycopg here to get the C implem in place of th pure python one
pip install "psycopg[c]"
pip install -r requirements.txt
echo --------------------------------CREATING A DATABASE-----------------------------
sudo -u postgres createdb seedify
echo -----------------------------------CREATING A USER------------------------------
echo Please enter a username :
read username
sudo -u postgres createuser $username --pwprompt
echo ----------------------------CREATING TABLES AND TESTING-------------------------
python3 ./db/initDB.py
