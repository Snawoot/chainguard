import logging

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from . import constants

def setup_logger(name, verbosity):
    logger = logging.getLogger(name)
    logger.setLevel(verbosity)
    handler = logging.StreamHandler()
    handler.setLevel(verbosity)
    handler.setFormatter(logging.Formatter('%(asctime)s '
                                           '%(levelname)-8s '
                                           '%(name)s: %(message)s',
                                           '%Y-%m-%d %H:%M:%S'))
    logger.addHandler(handler)
    return logger


def check_loglevel(arg):
    try:
        return constants.LogLevel[arg]
    except (IndexError, KeyError):
        raise argparse.ArgumentTypeError("%s is not valid loglevel" % (repr(arg),))


def check_positive_int(val):
    def fail():
        raise argparse.ArgumentTypeError("%s is not valid positive integer" % (repr(val),))
    try:
        ival = int(val)
    except ValueError:
        fail()
    if not 0 < ival:
        fail()
    return ival


def check_positive_float(val):
    def fail():
        raise argparse.ArgumentTypeError("%s is not valid positive float" % (repr(val),))
    try:
        ival = float(val)
    except ValueError:
        fail()
    if not 0 < ival:
        fail()
    return ival


def get_x509_domains(cert):
    names = []

    try:
        alt_names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = alt_names.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        pass

    if not names:
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names:
            common_name = common_names[0]
            names = [common_name.value]
    return names


