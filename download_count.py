__author__ = 'root'
import requests
import io


def dict_to_object(d):
    if '__class__' in d:
        class_name = d.pop('__class__')
        module_name = d.pop('__module__')
        module = __import__(module_name)
        class_ = getattr(module, class_name)
        args = dict((key.encode('ascii'), value) for key, value in d.items())
        inst = class_(**args)
    else:
        inst = d
    return inst


def ensure_str(s):
    if isinstance(s, unicode):
        s = s.encode('utf-8')
    return s

full_names = []


buf = io.StringIO()
r = requests.get('https://api.github.com/users/NORMA-Company/repos')
myobj = r.json()

for rep in myobj:
    full_names.insert(0, ensure_str(rep['full_name']))

for full_name in full_names:
    buf = io.StringIO()
    try:
        r = requests.get('https://api.github.com/repos/' + full_name + '/releases')
        myobj = r.json()
        for p in myobj:
            if "assets" in p:
                for asset in p['assets']:
                    print((asset['name'] + ": " + str(asset['download_count']) +
                          " downloads"))
            else:
                print("No data")
    except:
        pass