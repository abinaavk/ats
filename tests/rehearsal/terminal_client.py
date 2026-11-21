"""A browser-like Socket.IO client for the rehearsal (run with the Monitor's Python): drives /terminal on a chosen server."""
import re
import sys
import time

import requests
import socketio

url, password, server, mode = sys.argv[1:5]
http = requests.Session()
csrf = re.search(r'name="csrf_token" value="([^"]+)"', http.get(url + '/login').text)[1]
http.post(url + '/login', data={'password': password, 'csrf_token': csrf})
output, exits = [], []
client = socketio.Client(http_session=http)
client.on('terminal_output', lambda data: output.append(data), namespace='/terminal')
client.on('terminal_exit', lambda data: exits.append(data), namespace='/terminal')


def text():
    return ''.join(output)


def wait_for(condition, seconds=40, label=''):
    end = time.time() + seconds
    while time.time() < end:
        if condition():
            return
        time.sleep(0.05)
    print(f'TIMEOUT waiting for {label}; output so far: {text()[-400:]!r}')
    client.disconnect()
    sys.exit(1)


client.connect(url + '/?server=' + server, namespaces=['/terminal'], transports=['polling'])
if mode == 'bad':
    wait_for(lambda: exits, 30, 'a refusal')
    print('REFUSED:' + text().strip().replace('\r\n', ' '))
    client.disconnect()
    sys.exit(0)
client.emit('terminal_resize', {'rows': 31, 'cols': 93}, namespace='/terminal')
client.emit('terminal_input', {'input': 'echo via-monitor-$((6*7)); id -un; stty size\r'}, namespace='/terminal')
wait_for(lambda: 'via-monitor-42' in text() and '31 93' in text() and re.search(r'\nnobody\r?\n', text()), 40, 'command output as the service user')
client.emit('terminal_input', {'input': 'sleep 30\r'}, namespace='/terminal')
time.sleep(0.6)
client.emit('terminal_input', {'input': '\x03'}, namespace='/terminal')
client.emit('terminal_input', {'input': 'echo int-$?\r'}, namespace='/terminal')
wait_for(lambda: 'int-130' in text(), 30, 'Ctrl-C to interrupt the job, not the shell')
client.emit('terminal_input', {'input': "printf '\\342'; sleep .2; printf '\\202\\254-euro\\n'\r"}, namespace='/terminal')
wait_for(lambda: '€-euro' in text(), 30, 'UTF-8 split across reads')
if mode == 'abandon':
    client.disconnect()                      # closing the browser tab must end the shell on the Global
    print('ABANDONED')
    sys.exit(0)
client.emit('terminal_input', {'input': 'exit\r'}, namespace='/terminal')
wait_for(lambda: exits, 30, 'the session to end')
client.disconnect()
print('RELAYED_OK')
