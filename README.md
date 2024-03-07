# BASE PROJECT 🍃

❓️L'appli de recrutement préferée de ton recruteur préferé. <br>  
🟢 Status : https://status.carbonlab.dev

## 🏎️ getting started

### prerequisite :
- Python > 3.8
- PostgreSQL
- NginX (only if you need a reverse proxy)

### download :
      git clone git@gitlab.com:SLUG.git  
or download it manually

https://gitlab.com/SLUG/-/releases/RELEASE

### install :

0. install postgresql

       apt install postgresql postgresql-contrib -y
1. edit `server.ini` with your parameters


2. add the DKIM private key in `mailing/dkim.txt`

       nano mailing/dkim.txt

   or you can just copy your local file


3. Install the dependencies

       bash install.sh  
4. (optional) create a service to bundle it  
   edit `/misc/NAME.service` with your path then :

       bash ./misc/createService.sh  

5. (optional) open your firewall/ports and add a route in your reverse proxy

### one time run :

	sudo ./venv/bin/python server.py  

### starting the service :
	systemctl start NAME.service  


## 🖥️ Work
If you plan to commit something don't forget to IGNORE the *.ini file
run

	git update-index --assume-unchanged server.ini

## 🧶 Miscellaneous

### show logs :
	journalctl -u NAME  

### show status :
	systemctl status NAME  

### restart :
	systemctl restart NAME  

### kill a service running on PORT
	fuser -n tcp -k' PORT  

make this a command :

	nano .bashrc  
add

	alias killPort='fuser -n tcp -k'  
save and enjoy
