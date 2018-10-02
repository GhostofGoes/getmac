from os import path

def load_sample(filename):
    filename = path.realpath('%s/../samples/%s' % (path.dirname(__file__), filename))
    content = ''
    with open(filename, 'r') as f:
        content = f.read()
    return content
