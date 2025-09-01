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
        ex(f"rm -r {EMPTY_PROJECT_PATH}/static/home")
    else:
        if "ws" in features:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_sakura_ws.ini ./server.ini")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_sakura_ws.py ./server.py")
        else:
            ex(f"cp {EMPTY_PROJECT_PATH}/server_sakura.ini ./server.ini")
            ex(f"cp {EMPTY_PROJECT_PATH}/server_sakura.py ./server.py")

        ex(f"cp -r {EMPTY_PROJECT_PATH}/mailing ./")

        if "cron" in features:
            ex(f"cp -r {EMPTY_PROJECT_PATH}/crons ./")

    if "orm" in features or server == "sakura":
        ex(f"cp -r {EMPTY_PROJECT_PATH}/db ./")

    if "js" not in features:
        ex(f"rm -r {EMPTY_PROJECT_PATH}/static/framework")
        ex(f"rm -r {EMPTY_PROJECT_PATH}/static/translations")
        ex(f"rm {EMPTY_PROJECT_PATH}/static/mobileUiManifest.mjs")

    if "md" not in features:
        ex(f"rm -r {EMPTY_PROJECT_PATH}/static/markdown")

    if "ws" not in features:
        ex(f"rm -r {EMPTY_PROJECT_PATH}/static/ws")
    else:
        ex(f"cp {EMPTY_PROJECT_PATH}/misc/nginx_prod_ws ./misc/nginx_prod")
    ex(f"rm {EMPTY_PROJECT_PATH}/misc/nginx_prod_ws")


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
    convert = []
    for idx, feat in enumerate(features, 1):
        convert.append(feat)
        print(f"{idx}. {feat}")
    choice = input("Enter the numbers separated by commas (e.g., 1,3): ")
    selected = []
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


def main():
    print("Sakura CLI")
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
