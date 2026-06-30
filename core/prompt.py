import sys
import os
import tempfile


def prompt(default=None):
    if sys.platform == 'win32':
        import subprocess
        editor = os.environ.get('EDITOR', 'notepad.exe')
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            if default:
                f.write(default)
            tmpname = f.name
        subprocess.call([editor, tmpname])
        with open(tmpname, 'r') as f:
            result = f.read()
        os.unlink(tmpname)
        return result
    else:
        editor = os.environ.get('EDITOR', 'nano')
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
            if default:
                f.write(default)
            tmpname = f.name
        pid = os.fork()
        if pid == 0:
            os.execvp(editor, [editor, tmpname])
        else:
            import subprocess as _sp
            _sp.call([editor, tmpname])
        with open(tmpname, 'r') as f:
            result = f.read()
        os.unlink(tmpname)
        return result
