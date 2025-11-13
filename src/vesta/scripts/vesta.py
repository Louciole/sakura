import argparse
import os
import subprocess
from .utils import ex, Installer

HERE = os.path.dirname(__file__)
PATH = os.getcwd()
EMPTY_PROJECT_PATH = os.path.join(HERE, '..', 'emptyProject')

def list_features(server):
    if server == "http":
        return {
            "ORM: PostgreSQL ORM ": "ORM",
            "JS: Frontend Framework": "js",
            "MD: Js markdown parser": "md",
        }

    return {
        "Websockets: WS server": "ws",
        "JS: Frontend Framework": "js",
        "CRON: scheduled tasks": "cron",
        "MD: Js markdown parser": "md",
    }

def copy_features(server, features):
    ex(f"cp -r {EMPTY_PROJECT_PATH}/misc ./")
    ex(f"cp -r {EMPTY_PROJECT_PATH}/static ./")
    ex(f"cp -r {EMPTY_PROJECT_PATH}/tests ./")
    ex(f"cp {EMPTY_PROJECT_PATH}/.gitignore .")
    ex(f"cp {EMPTY_PROJECT_PATH}/CONTRIBUTING.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/LICENSE.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/README.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/install.sh .")
    ex(f"cp {EMPTY_PROJECT_PATH}/requirements.txt .")
    ex(f"cp {EMPTY_PROJECT_PATH}/.gitlab-ci.yml .")


    if server == "http":
        if "ORM" in features:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_static_orm.py ./server.py")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_static_orm.ini ./server.ini")
        else:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_static.py ./server.py")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_static.ini ./server.ini")
        ex(f"rm -r ./static/home")
    else:
        if "ws" in features:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_vesta_ws.ini ./server.ini")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_vesta_ws.py ./server.py")
        else:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_vesta.ini ./server.ini")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_vesta.py ./server.py")

        ex(f"cp -r {EMPTY_PROJECT_PATH}/mailing ./")

        if "cron" in features:
            ex(f"cp -r {EMPTY_PROJECT_PATH}/crons ./")

    if "orm" in features or server == "vesta":
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db ./")

    if "js" not in features:
        ex(f"rm -r ./static/framework")
        ex(f"rm -r ./static/translations")
        ex(f"rm ./static/mobileUiManifest.mjs")

    if "md" not in features:
        ex(f"rm -r ./static/markdown")

    if "ws" not in features:
        ex(f"rm -r ./static/ws")
    else:
        ex(f"cp {EMPTY_PROJECT_PATH}/misc/nginx_prod_ws ./misc/nginx_prod")
    ex(f"rm ./misc/nginx_prod_ws")
    manifest = server+"\n"
    for feat in features:
        manifest += feat + "\n"
    with open("vesta.manifest", "w+") as f:
        f.write(manifest)

def init_project():
    if os.path.exists("server.ini"):
        print("A Vesta project already exists in this directory.")
        return


    # Choose server type
    print("Choose server type:")
    print("1. HTTP (for static websites or simple apps without auth or websockets)")
    print("2. Vesta (with uniauth, ORM, mailing)")
    choice = input("Enter 1 or 2: ")
    if choice == '1':
        server = "http"
    elif choice == '2':
        server = "vesta"
    else:
        print("Invalid choice.")
        return

    features = list_features(server)

    print("Which features would you like to add to your project?")
    convert = []
    for idx, feat in enumerate(features, 1):
        convert.append(feat)
        print(f"{idx}. {feat}")
    choice = input("Enter the numbers separated by commas (e.g., 1,3): ")

    selected = []
    if choice.strip() != "":
        list = choice.split(',')
        for x in list:
            if x.strip().isdigit():
                i = int(x.strip()) - 1
                if 0 <= i < len(features):

                    selected.append(features[convert[i]])
                else:
                    print(f"Number is out of range: {x.strip()}")
                    return
            else:
                print(f"Invalid input: {x.strip()}")
                return


    copy_features(server,selected)
    print("Initialization complete.")

def installDeps():
    print("Installing dependencies...")
    server, features = getManifest()
    installFeatures(features)

    print("Dependencies installed.")

def getManifest():

    if not os.path.exists("vesta.manifest"):
        print("vesta.manifest not found. Are you in a Vesta project directory?")
        exit(1)


    with open("vesta.manifest", "r") as f:
        lines = f.readlines()
        server = lines[0].strip()
        features = [line.strip() for line in lines[1:]]
    return server, features

def installFeatures(features):
    if "md" in features:
        ex(f"cp -r {EMPTY_PROJECT_PATH}/static/markdown ./static/")

    if "js" in features:
        ex(f"cp -r {EMPTY_PROJECT_PATH}/static/framework ./static/")

def updateDeps():
    print("Updating Vesta...")
    server, features = getManifest()

    if "md" in features:
        ex(f"rm -r ./static/markdown")

    if "js" in features:
        ex(f"rm -r ./static/framework")
    installFeatures(features)

def main():
    parser = argparse.ArgumentParser(prog='vesta', description='Vesta project management CLI')
    subparsers = parser.add_subparsers(dest='command')

    # Commande init
    parser_init = subparsers.add_parser('init', help='Initialize a new Vesta project')
    parser_init = subparsers.add_parser('install', help='Import dependencies')
    parser_db = subparsers.add_parser('db', help='Manage the database')
    parser_update = subparsers.add_parser('update', help='Update dependencies')
    parser_test = subparsers.add_parser('test', help='Run tests')
    parser_add_feature = subparsers.add_parser('add-feature', help='Add a feature to the project')

    parser_nginx = subparsers.add_parser('nginx', help='Setup/manage nginx configuration')
    nginx_subparsers = parser_nginx.add_subparsers(dest='nginx_command')
    parser_nginx_setup = nginx_subparsers.add_parser('setup', help='Install nginx config')
    parser_nginx_mime = nginx_subparsers.add_parser('mime', help='Add mimetype for mjs files')
    parser_nginx_reset = nginx_subparsers.add_parser('reset', help='Reset nginx config')

    parser_service = subparsers.add_parser('service', help='Setup/manage systemD service')
    service_subparsers = parser_service.add_subparsers(dest='service_command')
    parser_service_setup = service_subparsers.add_parser('setup', help='Install systemd config')


    args = parser.parse_args()

    if args.command == 'init':
        init_project()
    elif args.command == 'db':
        pass
    elif args.command == 'update':
        updateDeps()
    elif args.command == 'install':
        installDeps()
    elif args.command == 'test':
        ex(f"python {HERE}/testsRun.py")
    elif args.command == 'add-feature':
        pass
    elif args.command == 'nginx':
        installer = Installer(PATH + "/server.ini", PATH)

        if args.nginx_command == 'setup':
            installer.installNginx()
        elif args.nginx_command == 'mime':
            installer.addNginxMimeType()
        elif args.nginx_command == 'reset':
            installer.nukeNginx()
            installer.installNginx(link=False)
        else:
            parser_nginx.print_help()

    elif args.command == 'service':
        installer = Installer(PATH + "/server.ini", PATH)

        if args.service_command == 'setup':
            installer.installService()
        else:
            parser_service.print_help()
    else:
        parser.print_help()
