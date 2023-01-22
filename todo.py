from mimetypes import init
import pprint
import json
import bcrypt
from pymongo import MongoClient
from getpass import getpass
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts


to_do_list = []


def auth_user():
    client = MongoClient()
    db = client.to_do
    authentication = db.authentication
    user_input = input(f"For Sign-in press 1 \nFor New users press 2 to Register ")
    match user_input:
        case '1':
            user_name = input("Enter username ")
            password = getpass("Enter password: ")
            password_enc = bytes(password,'utf-8')

            finder = authentication.find_one({"user_upper":user_name.upper()})
            if finder is not None:
                stored_pass = finder["password"]
                if bcrypt.checkpw(password_enc, stored_pass):
                    print("Login success")
                else:
                    print("The Username/Password combination is incorrect")
            else:
                print("The Username/Password combination is incorrect")


                

        case '2':
            while True:
                user_name = input("Enter username ")
                finder = authentication.find_one({"user_upper":user_name.upper()})
                if finder is None:
                    password = getpass("Enter password: ")
                    salt = bcrypt.gensalt()
                    password_enc = bytes(password,'utf-8')
                    hashed = bcrypt.hashpw(password_enc,salt)
                    auth_cred = {"username": user_name,
                                "user_upper": user_name.upper(),
                                "password" : hashed
                    }
                    authentication.insert_one(auth_cred).inserted_id
                    break
                else:
                    print(f"username {user_name} exists already")


            # if to_do.lower() not in to_do_list:
            # password = input("Enter password")
            # else:

auth_user()
def main():
    while True:
        user_input = input("Type 'Add', 'Show' or 'Exit': ").lower()

        match user_input:
            case 'add':
                to_do = input("Enter a to do item: ")
                if to_do.lower() not in to_do_list:
                    to_do_list.append(to_do)
                    print("\n item added\n")
                else:
                    print("item already in to do list \n")

            case 'show':
                if len(to_do_list)==0:
                    print("no items in list")

                for item in to_do_list:
                    print("*",item,)
                print("\n")

            case 'delete':
                to_delete = user_input(

                )
            case 'exit':
                break


def importance_assigner(list_items):
    list1,list2,list3,list4 = [],[],[],[]
    for item in list_items:
        while True:
            eisenhower_i = int(user_input(f"what Eisenhower quadrant does the item *{item}* belong ? "))
            if eisenhower_i == 1:
                list1.append(item)
            elif eisenhower_i == 2:
                list2.append(item)
            elif eisenhower_i == 3:
                list3.append(item)
            elif eisenhower_i == 4:
                list4.append(item)
            else:
                break



"""
class TodoList:
    def __init__(self) -> None:
        pass
"""
