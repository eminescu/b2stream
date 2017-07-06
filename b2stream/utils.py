
def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def filter_dict(d, ignore_keys):
    return { k: d[k] for k in d if not k in ignore_keys }

from progress.bar import Bar
class DownloadBar(Bar):
    suffix = '%(hindex)9s %(percent)5.1f%%'

    @property
    def hindex(self):
        return sizeof_fmt( self.index )

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.finish()

class UploadBar(DownloadBar):
    pass
    # suffix = '%(hindex)9s %(percent)5.1f%%'

    # def update_avg(self, n, dt):
    #     if n > 0:
    #         self._xput.append(n / dt)
    #         self.avg = sum(self._xput) / len(self._xput)

    # @property
    # def hindex(self):
    #     return sizeof_fmt( self.index )

class ProgressListener:
    def __init__(self, content_length):
        self.bar = UploadBar('Uploading', max=content_length)

    def bytes_completed(self, n):
        self.bar.next(n-self.bar.index)

    def close(self):
        self.bar.finish()

