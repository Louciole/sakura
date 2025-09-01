import argparse
import os
import subprocess

EMPTY_PROJECT_PATH = os.path.join(os.path.dirname(__file__), '..', 'emptyProject')

def ex( command):
    subprocess.run(command, shell=True, check=True)

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
    ex(f"cp {EMPTY_PROJECT_PATH}/misc/sakura.service ./misc/")
    ex(f"cp {EMPTY_PROJECT_PATH}/misc/nginx_local ./misc/")
    ex(f"cp {EMPTY_PROJECT_PATH}/static/main.html ./static/")
    ex(f"cp {EMPTY_PROJECT_PATH}/static/main.mjs ./static/")
    ex(f"cp {EMPTY_PROJECT_PATH}/static/style.css ./static/")
    ex(f"cp {EMPTY_PROJECT_PATH}/.gitignore .")
    ex(f"cp {EMPTY_PROJECT_PATH}/CONTRIBUTING.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/LICENSE.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/README.md .")
    ex(f"cp {EMPTY_PROJECT_PATH}/install.sh .")
    ex(f"cp {EMPTY_PROJECT_PATH}/requirements.txt .")

    if server == "http":
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db/server_static.py ./server.py")
    else:
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db/server_sakura.py ./server.py")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db/initDB.py ./db/")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db/models.py ./db/")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db/migrations ./db/")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/auth ./")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/templates ./")
        ex(f"cp -r {EMPTY_PROJECT_PATH}/emails ./")

        # print(f"Feature '{feat}' added to the project.")


src = os.path.join(EMPTY_PROJECT_PATH, feature)
    if not os.path.exists(src):
        print(f"Unknown feature: {feature}")
        return



def init_project():
    if os.path.exists("server.ini"):
        print("A Sakura project already exists in this directory.")
        return


    # Choose server type
    print("Choose server type:")
    print("1. HTTP (for static websites or simple apps without auth or websockets)")
    print("2. Sakura (with uniauth, ORM, mailing)")
    choice = input("Enter 1 or 2: ")
    if choice == '1':
        server = "http"
    elif choice == '2':
        server = "sakura"
    else:
        print("Invalid choice.")
        return

    features = list_features(server)

    print("Which features would you like to add to your project?")
    for idx, feat in enumerate(features, 1):
        print(f"{idx}. {feat}")
    choix = input("Enter the numbers separated by commas (e.g., 1,3): ")
    try:
        indices = [int(x.strip())-1 for x in choix.split(',') if x.strip().isdigit()]
        selected = [features[i] for i in indices if 0 <= i < len(features)]
    except Exception:
        print("Invalid input.")
        return
    dest = os.getcwd()
    copy_features(server,selected)
    print("Initialization complete.")


def main():
    parser = argparse.ArgumentParser(prog='sakura', description='Sakura project management CLI')
    subparsers = parser.add_subparsers(dest='command')

    # Commande init
    parser_init = subparsers.add_parser('init', help='Initialize a new Sakura project')
    parser_db = subparsers.add_parser('db', help='Manage the database')
    parser_update = subparsers.add_parser('update', help='Update Sakura')
    parser_test = subparsers.add_parser('test', help='Run tests')
    parser_add_feature = subparsers.add_parser('add-feature', help='Add a feature to the project')

    args = parser.parse_args()

    if args.command == 'init':
        init_project()
    elif args.command == 'db':
        pass
    elif args.command == 'update':
        pass
    elif args.command == 'test':
        pass
    elif args.command == 'add-feature':
        pass
    else:
        parser.print_help()
