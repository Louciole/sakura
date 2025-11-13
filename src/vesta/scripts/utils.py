import subprocess
from configparser import ConfigParser


def ex(command):
    subprocess.run(command, shell=True, check=True)

class Installer:
    def __init__(self, configFile, path):
        self.PATH = path
        self.importConf(configFile)
        self.uniauth = "N"
        self.name = self.config.get("server", "SERVICE_NAME").replace(" ", "_").lower()

    def installNginx(self, link=True):
        print("----NGINX----")

        if self.config.getboolean("server", "DEBUG"):
            self.editFile("misc/nginx_local", {"[PATH]": self.PATH, "[SERV-PORT]": self.config.get("server", "PORT")})
            ex("sudo cp ./misc/nginx_local_filled /etc/nginx/sites-available/" + self.name)
        else:
            try:
                self.editFile("misc/nginx_prod", {"[PATH]": self.PATH, "[SERV-PORT]": self.config.get("server", "PORT"), "[WS-PORT]": self.config.get("NOTIFICATION", "PORT")})
            except Exception:
                self.editFile("misc/nginx_prod", {"[PATH]": self.PATH, "[SERV-PORT]": self.config.get("server", "PORT")})
            ex("sudo cp ./misc/nginx_prod_filled /etc/nginx/sites-available/" + self.name)

        if not link:
            return

        ex("sudo ln -s /etc/nginx/sites-available/" + self.name + " /etc/nginx/sites-enabled/")

    def addNginxMimeType(self):
        pattern = 'application/javascript'
        new_line = 'application/javascript mjs;'
        with open('/etc/nginx/mime.types', 'r+') as f:
            lines = f.readlines()
            found = False
            for i, line in enumerate(lines):
                if pattern in line:
                    found = True
                    lines.insert(i + 1, new_line + '\n')
                    break
            if not found:
                print(f"Pattern '{pattern}' not found in {filename}.")
            else:
                f.seek(0)
                f.writelines(lines)

    def setupCrons(self):
        try:
            ex("crontab -l > crontab")
        except Exception:
            pass
        ex("echo '*/15 * * * * " + self.PATH + "/venv/bin/python3 " + self.PATH + "/crons/15mins.py' >> crontab")
        ex("echo '0 * * * * " + self.PATH + "/venv/bin/python3 " + self.PATH + "/crons/1h.py' >> crontab")
        ex("echo '0 0 * * * " + self.PATH + "/venv/bin/python3 " + self.PATH + "/crons/1day.py' >> crontab")
        ex("crontab crontab")

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(configFile)
            print("config at " + configFile + " loaded")
        except Exception:
            print("please create a config file")

    def nukeNginx(self):
        ex("sudo rm /etc/nginx/sites-available/" + self.name)

    def installService(self):
        self.editFile("misc/vesta.service", {"[PATH]": self.PATH, "[SERV-PORT]": self.config.get("server", "PORT"), "[NAME]":self.config.get("server", "service_name")} )
        ex("cp ./misc/vesta.service_filled /etc/systemd/system/" + self.name + ".service")
        ex("sudo systemctl daemon-reload")
        ex("sudo systemctl enable " + self.name + ".service")
        ex("sudo systemctl start " + self.name + ".service")

    def editFile(self, file, templates):
        with open(file, "r+") as f:
            data = f.read()
            for key in templates:
                data = data.replace(key, templates[key])
        with open(file+"_filled", "w+") as f:
            f.write(data)