import re
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    import unicodedata
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\s\-.]', '', value).strip())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value

def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    return load_pem_x509_certificate(data, get_backend(backend))

