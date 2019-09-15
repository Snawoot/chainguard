import logging
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

