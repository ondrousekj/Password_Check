import sys
import requests
import hashlib


def hash_the_pass(password):
    '''
    Function encrypts the password parameter using SHA1 hash encryption
    :param password:
    :return:
    '''
    hashed = hashlib.new("sha1")
    hashed.update(bytes(password, "utf-8"))
    return hashed.hexdigest().upper()


def k_anon_hash(hash):
    '''
    Function anonymizes the parameter hash in accordance with rules of k-anonymity
    :param hash:
    :return:
    '''
    k_hash = hash[:5]
    hash_tail = hash[5:]
    return k_hash, hash_tail


def request_hash_data(query):
    '''
    requests the information about the query paramenter (password to be checked) from API and returns request and
    unanonymized part of query hash.
    :param query:
    :return:
    '''
    k_hash, tail = k_anon_hash(hash_the_pass(query))
    url = "https://api.pwnedpasswords.com/range/" + k_hash
    req = requests.get(url)
    if req.status_code != 200:
        raise RuntimeError(f"Error while fetching the dat - Code: {req.status_code}")
    return req, tail

def resolve_data(arg):
    '''
    controls if eneterd password exists in database of breached passwords.
    :param arg:
    :return:
    '''
    req, tail = request_hash_data(arg)
    hashes = req.text.splitlines()
    hash_w_count = (line.split(":") for line in hashes)
    for h, c in hash_w_count:
        if h == tail:
            return int(c)
    return 0


def report_result(breach_count):
    '''
    Reports safety of password being checked based on number of reported breaches.
    :param breach_count:
    :return:
    '''
    if breach_count > 0:
        bad_call = f"WARNING! Change your password! It was breached {str(breach_count)} times."
        return bad_call
    else:
        good_call = "No worry, your password is so far safe."
        return good_call

def run_checker(argv):
    '''
    runs the base function for checking passwords, which are being passed to the script as cmd arguments.
    If no argument is eneterd, function raises Runtime Error.
    :param argv:
    :return:
    '''
    if len(argv) > 1:
        for arg in argv[1:]:
            print(f"Password '{arg}' - {report_result(resolve_data(arg))}")
    else:
        raise RuntimeError("You must enter the password you want to check!")

run_checker(sys.argv)
