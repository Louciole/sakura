echo --------------------------INSTALLING PYTHON DEPENDENCIES------------------------
sudo apt install build-essential -y
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.11
sudo apt install python3.11-dev -y
sudo apt install libpq-dev -y
sudo apt install python3.11-venv -y
python3.11 -m venv ./venv/
source venv/bin/activate
#installing psycopg here to get the C implem in place of th pure python one
pip install "psycopg[c]"
pip install git+https://gitlab.com/Louciole/sakura.git/
pip install -r requirements.txt
echo --------------------------------CREATING A DATABASE-----------------------------
echo Please enter a db name :
read dbName
sudo -u postgres createdb $dbName
echo -----------------------------------CREATING A USER------------------------------
echo Please enter a username :
read username
sudo -u postgres createuser $username -s --pwprompt
echo ----------------------------CREATING TABLES AND TESTING-------------------------
echo 'do you want to create a uniauth database? (y/n)'
read uniauth
if [ $uniauth == 'y' ] || [ $uniauth == 'Y' ]
then
  echo Please enter a db name :
  read uniauthName
  sudo -u postgres createdb $dbName
fi
python3 ./db/initDB.py $uniauth
echo ----------------------------ADDING A NGINX CONF-------------------------
echo 'do you want to add a configuration in nginx? (y/n)'
read nginx
if [ $nginx == 'y' ] || [ $nginx == 'Y' ]
then 
  sudo apt install nginx
  sudo systemctl start nginx
  echo 'what name you want for your conf? (without the .conf)'
  read nginxName
  sudo cp ./misc/nginx.conf /etc/nginx/sites-available/$nginxName.conf
  sudo ln -s /etc/nginx/sites-available/$nginxName.conf /etc/nginx/sites-enabled/$nginxName.conf
  sudo systemctl reload nginx
fi
